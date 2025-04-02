import os
from typing import Dict, List, Optional
import boto3
from botocore.config import Config
import logging
import time

logger = logging.getLogger()
loglevel = os.getenv("LOG_LEVEL", "INFO")  # Set to DEBUG for detailed logging
logger.setLevel(loglevel)

ACCOUNTS_ROLE = os.environ.get('ACCOUNTS_ROLE_NAME')

# Function to assume role in each account
def assume_role_in_account(account_id):
    sts_client = boto3.client('sts')
    assumed_role = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{ACCOUNTS_ROLE}",
        RoleSessionName="AutoTaggingSession"
    )
    return assumed_role['Credentials']

# Function to get accounts under an OU and its child OUs
def get_all_accounts_from_ous(ou_ids, organizations=None):
    if organizations is None:
        organizations = boto3.client("organizations")
        
    all_accounts = []

    for ou_id in ou_ids:
        accounts_in_ou = get_accounts_in_ou(ou_id, organizations)
        all_accounts.extend(accounts_in_ou)

    return all_accounts

# Function to get accounts under a specific OU (including child OUs)
def get_accounts_in_ou(ou_id, organizations=None):
    if organizations is None:
        organizations = boto3.client("organizations")
    
    accounts = []

    try:
        # Get accounts in the given OU
        response = organizations.list_accounts_for_parent(ParentId=ou_id)
        while True:
            for acc in response['Accounts']:
                if acc['Status'] == 'ACTIVE':
                    acc['JoinedTimestamp'] = str(acc['JoinedTimestamp'])
                    accounts.append(acc)

            # Check if there are more accounts to list
            if "NextToken" not in response:
                break
            else:
                response = organizations.list_accounts_for_parent(
                    ParentId=ou_id, NextToken=response["NextToken"]
                )

        # Get child OUs for the given OU
        child_ous = organizations.list_organizational_units_for_parent(ParentId=ou_id)
        for ou in child_ous['OrganizationalUnits']:
            # Recursively call the function for each child OU
            accounts.extend(get_accounts_in_ou(ou['Id'], organizations))

        return accounts

    except Exception as errorMsg:
        raise Exception(f"ERROR: getting accounts for OU {ou_id}: {str(errorMsg)}")

# Main function to tag resources for all accounts in a list of OU IDs
def tag_resources_for_ous(ou_ids, desired_tags, TAG_RESOURCES_CHUNK_SIZE):
    logger.info(f"TAG_RESOURCES_CHUNK_SIZE: {TAG_RESOURCES_CHUNK_SIZE}")
    try:
        # Get all accounts from the OUs and their child OUs
        all_accounts = get_all_accounts_from_ous(ou_ids)
        accounts_length = len(all_accounts)
        account_num = 1

        # Process each account
        for account in all_accounts:
            account_id = account['Id']
            logger.info(f"Assuming role for account {account_id} - {account_num} out of {accounts_length}")
            account_num += 1

            # Assume the role in the target account
            credentials = assume_role_in_account(account_id)
            # Create a session for the assumed role
            assumed_resource_tagging_client = boto3.client(
                'resourcegroupstaggingapi',
                config=Config(connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}),
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

            assumed_resource_explorer_client = boto3.client(
                'resource-explorer-2',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

            if os.getenv("PROPAGATE_ACCOUNT_TAGS", "false").lower() == "true":
                try:
                    accountTags = get_organization_tags(account_id)
                    logger.info(f"Account tags: {accountTags}")
                    # Normalize accountTags to a list of tuples
                    accountTags = [(tag['Key'], tag['Value']) for tag in accountTags if 'Key' in tag and 'Value' in tag]
                    logger.info(f"Normalized account tags: {accountTags}")
                    accountTags.extend(desired_tags.items())
                    # logger.info(f"Account tags: {accountTags}")
                    desired_tags.clear()
                    desired_tags.update(dict(accountTags))
                    logger.info(f"Updated desired tags: {desired_tags}")
                except Exception as e:
                    logger.error(f"Error getting account tags: {str(e)}")
                    raise Exception(f"Error getting account tags: {str(e)}") from e
            else:
                logger.info("Account tags propagation is disabled.")

            try:
                logger.info("Attempting to create AutoTaggingView in Resource Explorer")
                create_view_command_output = assumed_resource_explorer_client.create_view(
                    ViewName="AutoTaggingView", IncludedProperties=[{"Name": "tags"}]
                )
                view_arn = create_view_command_output["View"]["ViewArn"]
            except Exception as e:
                logger.info(f"Exception occurred: {str(e)}")
                logger.info("Failed to create new resource explorer view, attempting to import the solution-managed view")
                list_view_command_output = assumed_resource_explorer_client.list_views()
                auto_tagging_view_view_arn: list[Optional[str]] = [
                    view_arn
                    for view_arn in list_view_command_output["Views"]
                    if "AutoTaggingView" in view_arn
                ]
                if len(auto_tagging_view_view_arn) != 1:
                    raise Exception(
                        "Failed to create and locate solution-managed view from the Resource Explorer client"
                    )
                view_arn = auto_tagging_view_view_arn[0]
                
            logger.info("Fetching all resources that do not include the required tags")
            tag_search_query_string = get_search_query_string()
            logger.info(f"ResourceExplorer QueryString: {tag_search_query_string}")
            resource_arns_to_tag: List[str] = []
            if "*" in resources:
                resource_arns_to_tag = get_results(
                    assumed_resource_explorer_client, tag_search_query_string, view_arn
                )
            else:
                # batch_size = 10
                batch_size = 30
                for i in range(0, len(resources), batch_size):
                    batch = resources[i : i + batch_size]
                    logger.info(f"Processing batch: {batch}")  # Debug log for the batch
                    resource_type_search_query_string = ""
                    for count, resource in enumerate(batch, start=1):
                        # resource_type_search_query_string += f'"resource" '
                        resource_type_search_query_string += '"{}" '.format(resource.replace(":","\:"))
                    resource_arns_to_tag.extend(
                        get_results(
                            assumed_resource_explorer_client,
                            f"{resource_type_search_query_string} {tag_search_query_string}",
                            view_arn,
                        )
                    )

            logger.info(f"Found {len(resource_arns_to_tag)} resources that should be tagged using the following tags: {desired_tags}")

            if resource_arns_to_tag:
                try:
                    logger.info(f"Resource ARNs to tag: {resource_arns_to_tag}")
                    logger.info("Start tagging resources using AWS Resource Tagging API")
                    logger.info(f"TAG_RESOURCES_CHUNK_SIZE: {TAG_RESOURCES_CHUNK_SIZE}")
                    tag_resources_in_chunks(assumed_resource_tagging_client, resource_arns_to_tag, desired_tags, TAG_RESOURCES_CHUNK_SIZE)
                except Exception as e:
                    logger.error(f"Error occurred while tagging resources: {str(e)}")
            try:                
                assumed_resource_explorer_client.delete_view(ViewArn=view_arn)
            except Exception as e:
                logger.error(f"Failed to delete view: {view_arn}")

            logger.info(f"Finished tagging resources for account {account_id}")

    except Exception as e:
        logger.error(f"Error tagging resources for OUs: {str(e)}")
        raise


ACCOUNTS_ROLE = os.environ.get('ACCOUNTS_ROLE_NAME')

def tag_resources_in_chunks(aws_resource_tagging_client, resource_arns_to_tag, desired_tags, TAG_RESOURCES_CHUNK_SIZE):
    """Tag resources in chunks with retries and backoff to avoid throttling"""
    retries = 1  # Maximum number of retries for each chunk
    sleep_time = 5

    # Process resources in chunks
    for count in range(0, len(resource_arns_to_tag), TAG_RESOURCES_CHUNK_SIZE):
        chunk = list(set(resource_arns_to_tag[count : count + TAG_RESOURCES_CHUNK_SIZE]))  # Deduplicate and get a chunk
        logger.info(f"Attempting to tag {len(chunk)} resources.")

        # Try tagging with exponential backoff
        for attempt in range(retries):
            try:
                # Call the tag_resources API for the current chunk
                res = aws_resource_tagging_client.tag_resources(
                    ResourceARNList=chunk,
                    Tags=desired_tags
                )
                logger.info(f"Successfully tagged resources: {res}")
                
                if "FailedResourcesMap" in res and len(res["FailedResourcesMap"]) > 0:
                    failed_resources = res["FailedResourcesMap"]
                    logger.error(f"Failed to tag resources: {failed_resources}")
                    logger.error(f"Throttling exception occurred on attempt {attempt + 1}, retrying... ")
                    if attempt == retries - 1:
                        logger.error(f"Max retries exceeded for chunk: {chunk}. Skipping this chunk.")
                        break  # Skip the chunk after max retries
    
                    # If there are failed resources, we will retry the operation for them
                    failed_chunk = list(failed_resources.keys())
                    if failed_chunk:
                        logger.info(f"Retrying {len(failed_chunk)} failed resources: {failed_chunk}")
                        chunk = failed_chunk  # Set the chunk to failed resources for the next retry
                        logger.info(f"Sleeping for {sleep_time} seconds due to failed attempts")
                        time.sleep(sleep_time)
                        continue  # Retry the operation for the failed resources

                break  # If there are no failed resources or all are handled, break out of the retry loop            
        
            except Exception as e:
                logger.error(f"Failure in tagging operation, detailed error: {e}. Skipping this chunk.")
                break  # If an error occurs other than throttling, skip this chunk

        # Sleep between attempts if throttling occurs
        if attempt < retries - 1:
            logger.info(f"Sleeping for {sleep_time} seconds after attempt")
            time.sleep(sleep_time) 
        
    logger.info("Finished tagging resources.")


def parse_key_value_string(kv_string: str) -> dict:
    """
    Parse a string of format 'key=value1,key2=value2' into a dictionary
    
    Args:
        kv_string (str): String in format 'key=value1,key2=value2'
        
    Returns:
        dict: Dictionary of key-value pairs
        
    Example:
        >>> parse_key_value_string('name=john,age=25')
        {'name': 'john', 'age': '25'}
    """
    try:
        if not kv_string or kv_string.isspace():
            return {}

        # Split by comma and filter out empty strings
        pairs = [pair for pair in kv_string.split(',') if pair]

        # Create dictionary from key-value pairs
        result = {}
        for pair in pairs:
            # Skip empty pairs
            if not pair or '=' not in pair:
                continue

            key, value = pair.split('=', 1)  # Split on first '=' only
            # Strip whitespace and add to dict
            key = key.strip()
            value = value.strip()

            if key:  # Only add if key is not empty
                result[key] = value

        return result

    except Exception as e:
        logger.error(f"Error parsing key-value string: {str(e)}")
        raise ValueError(f"Invalid key-value string format: {kv_string}")

def get_search_query_string() -> str:
    if not bool(os.getenv("GLOBAL", "false")):
        search_query_string = ""
    else:
        search_query_string = f"region:{os.environ['AWS_REGION']} "
    for key, value in desired_tags.items():
        search_query_string += f"-tag:{key}={value} "
    # Add resourcetype.supports:tags to find only taggable resources 
    search_query_string += f"resourcetype.supports:tags "
    search_query_string += f"-service:cloudformation "
    return search_query_string

def get_results(client, query_string, view_arn):
    re_search_paginator = client.get_paginator("search")
    resource_arns_to_tag = []
    for page_number, page in enumerate(re_search_paginator.paginate(ViewArn=view_arn, QueryString=query_string), 1):
        for aws_resource in page["Resources"]:
            resource_arns_to_tag.append(aws_resource["Arn"])
    return resource_arns_to_tag

def get_organization_tags(account_id: str) -> List[Dict[str, str]]:
    """
    Get all tags for a specific account in the organization
    
    Args:
        account_id (str): AWS Account ID
        
    Returns:
        List[Dict[str, str]]: List of tags as key-value pairs
    """
    try:
        org_client = boto3.client('organizations')
        tags = []

        # Use paginator to handle pagination
        paginator = org_client.get_paginator('list_tags_for_resource')
        page_iterator = paginator.paginate(
            ResourceId=account_id
        )

        for page in page_iterator:
            if 'Tags' in page:
                tags.extend(page['Tags'])

        return tags

    except Exception as e:
        logger.error(f"Error getting tags for account {account_id}: {str(e)}")
        raise

def parse_comma_separated_list_with_validation(comma_separated_str: str, delimiter: str, allow_spaces: bool) -> List[str]:
    """
    Parse and validate service string with format checking
    
    Args:
        comma_separated_str (str): String in format '[service:resource,service2:resource2]'
        
    Returns:
        list: List of validated service strings
    """
    try:
        # Special case is all resources are required
        if comma_separated_str in ('["*"]', '*'):
            return ["*"]
        # Remove brackets, spaces and split by comma
        cleaned = comma_separated_str.strip('[]').strip()
        if not allow_spaces:
            cleaned = cleaned.replace(" ", "")
        if not cleaned:
            return []

        services = []
        for service in cleaned.split(','):
            service = service.strip()
            if not service:
                continue

            # Validate service:resource format
            if delimiter not in service:
                print(f"Warning: Invalid service format '{service}', skipping")
                continue

            service_parts = service.split(delimiter)
            if len(service_parts) != 2:
                print(f"Warning: Invalid service format '{service}', skipping")
                continue

            services.append(service)

        return services

    except Exception as e:
        print(f"Error parsing service string: {str(e)}")
        return []

desired_tags: Dict[str, str] = parse_key_value_string(os.environ["RESOURCE_TAGS"])
resources: List[str] = parse_comma_separated_list_with_validation(os.getenv("RESOURCES", '["*"]'), ":", False)
ou_ids : List[str] = os.environ["OU_IDS"].split(",")
tag_all_available_resources = resources == ["*"]

def lambda_handler(event, context):
    TAG_RESOURCES_CHUNK_SIZE = 5

    # Tag resources for all accounts in the specified OUs
    tag_resources_for_ous(ou_ids, desired_tags, TAG_RESOURCES_CHUNK_SIZE)