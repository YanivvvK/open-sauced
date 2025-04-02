import os
from typing import Dict, List, Optional, Set
import boto3
from botocore.config import Config
import logging
import time
import re

logger = logging.getLogger()
loglevel = os.getenv("LOG_LEVEL", "INFO")  # Set to DEBUG for detailed logging
logger.setLevel(loglevel)

ACCOUNTS_ROLE = os.environ.get('ACCOUNTS_ROLE_NAME')

# Function to assume role in each account
def assume_role_in_account(account_id):
    sts_client = boto3.client('sts')
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{ACCOUNTS_ROLE}",
            RoleSessionName="AutoTaggingSession"
        )
        return assumed_role['Credentials']
    except Exception as e:
        logger.error(f"Error assuming role in account {account_id}: {str(e)}")
        raise

# Function to get accounts under an OU and its child OUs
def get_all_accounts_from_ous(ou_ids, organizations=None):
    if organizations is None:
        organizations = boto3.client("organizations")
        
    all_accounts = []

    for ou_id in ou_ids:
        try:
            accounts_in_ou = get_accounts_in_ou(ou_id, organizations)
            all_accounts.extend(accounts_in_ou)
        except Exception as e:
            logger.error(f"Error getting accounts for OU {ou_id}: {str(e)}")

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
    
    # Track problematic resources across all accounts
    global_problematic_resources = set()
    
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

            try:
                # Assume the role in the target account
                credentials = assume_role_in_account(account_id)
                
                # Create sessions for the assumed role with appropriate timeout and retry settings
                config = Config(
                    connect_timeout=10,
                    read_timeout=60,
                    retries={'max_attempts': 5, 'mode': 'standard'},
                    tcp_keepalive=True
                )
                
                # Create a session for the assumed role
                assumed_resource_tagging_client = boto3.client(
                    'resourcegroupstaggingapi',
                    config=config,
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )

                assumed_resource_explorer_client = boto3.client(
                    'resource-explorer-2',
                    config=config,
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )

                # Handle account tag propagation
                account_tags = {}
                if os.getenv("PROPAGATE_ACCOUNT_TAGS", "false").lower() == "true":
                    try:
                        account_tags = get_organization_tags(account_id)
                        logger.info(f"Account tags: {account_tags}")
                        # Normalize accountTags to a list of tuples
                        account_tags = [(tag['Key'], tag['Value']) for tag in account_tags if 'Key' in tag and 'Value' in tag]
                        logger.info(f"Normalized account tags: {account_tags}")
                        account_tags.extend(desired_tags.items())
                        # Update desired_tags with account tags
                        tags_for_account = dict(account_tags)
                        logger.info(f"Updated desired tags: {tags_for_account}")
                    except Exception as e:
                        logger.error(f"Error getting account tags: {str(e)}")
                        # Continue with the original desired_tags if we can't get account tags
                        tags_for_account = desired_tags.copy()
                else:
                    logger.info("Account tags propagation is disabled.")
                    tags_for_account = desired_tags.copy()

                # Create or get the Resource Explorer view
                view_arn = None
                try:
                    logger.info("Attempting to create AutoTaggingView in Resource Explorer")
                    create_view_command_output = assumed_resource_explorer_client.create_view(
                        ViewName="AutoTaggingView", 
                        IncludedProperties=[{"Name": "tags"}]
                    )
                    view_arn = create_view_command_output["View"]["ViewArn"]
                except Exception as e:
                    logger.info(f"Failed to create new resource explorer view: {str(e)}")
                    try:
                        logger.info("Attempting to locate existing AutoTaggingView")
                        list_view_command_output = assumed_resource_explorer_client.list_views()
                        auto_tagging_views = [
                            view["ViewArn"]
                            for view in list_view_command_output["Views"]
                            if "AutoTaggingView" in view["ViewArn"]
                        ]
                        if auto_tagging_views:
                            view_arn = auto_tagging_views[0]
                        else:
                            # If no view exists with AutoTaggingView name, try to get the default view
                            logger.info("No AutoTaggingView found, attempting to get default view")
                            default_view = assumed_resource_explorer_client.get_default_view()
                            view_arn = default_view.get("ViewArn")
                    except Exception as inner_e:
                        logger.error(f"Failed to locate any usable Resource Explorer view: {str(inner_e)}")
                        continue  # Skip this account if no view can be created or found
                
                if not view_arn:
                    logger.error("No valid Resource Explorer view available, skipping account")
                    continue
                    
                # Build the search query with exclusions
                tag_search_query_string = get_search_query_string(tags_for_account)
                logger.info(f"ResourceExplorer QueryString: {tag_search_query_string}")
                
                # Get resources to tag
                resource_arns_to_tag: List[str] = []
                
                if "*" in resources:
                    # Get all taggable resources
                    resource_arns_to_tag = get_results(
                        assumed_resource_explorer_client, tag_search_query_string, view_arn
                    )
                else:
                    # Get resources by specified resource types
                    batch_size = 30
                    for i in range(0, len(resources), batch_size):
                        batch = resources[i : i + batch_size]
                        logger.debug(f"Processing batch: {batch}")
                        resource_type_search_query_string = ""
                        for resource in batch:
                            resource_type_search_query_string += f'"{resource.replace(":","\:")}" '
                        full_query = f"{resource_type_search_query_string} {tag_search_query_string}"
                        
                        try:
                            batch_resources = get_results(
                                assumed_resource_explorer_client,
                                full_query,
                                view_arn,
                            )
                            resource_arns_to_tag.extend(batch_resources)
                        except Exception as e:
                            logger.error(f"Error searching for resources in batch {batch}: {str(e)}")
                
                # Filter out known problematic resources
                filtered_resources = filter_problematic_resources(resource_arns_to_tag, global_problematic_resources)
                
                logger.info(f"Found {len(filtered_resources)} resources that should be tagged using the following tags: {tags_for_account}")

                if filtered_resources:
                    try:
                        logger.debug(f"Resource ARNs to tag: {filtered_resources}")
                        logger.info("Start tagging resources using AWS Resource Tagging API")
                        
                        # Tag resources and get updated problematic resources
                        new_problematic = tag_resources_in_chunks(
                            assumed_resource_tagging_client, 
                            filtered_resources, 
                            tags_for_account, 
                            TAG_RESOURCES_CHUNK_SIZE
                        )
                        
                        # Update global problematic resources
                        global_problematic_resources.update(new_problematic)
                        
                    except Exception as e:
                        logger.error(f"Error occurred while tagging resources: {str(e)}")
                else:
                    logger.info("No resources to tag after filtering")
                
                # Clean up the Resource Explorer view
                try:                
                    if "AutoTaggingView" in view_arn:
                        assumed_resource_explorer_client.delete_view(ViewArn=view_arn)
                        logger.info(f"Deleted temporary view: {view_arn}")
                except Exception as e:
                    logger.error(f"Failed to delete view {view_arn}: {str(e)}")

                logger.info(f"Finished tagging resources for account {account_id}")
                
            except Exception as account_error:
                logger.error(f"Error processing account {account_id}: {str(account_error)}")
                # Continue to the next account

        logger.info(f"Completed tagging process for all accounts. Problematic resources count: {len(global_problematic_resources)}")
        if global_problematic_resources and logger.level <= logging.DEBUG:
            logger.debug(f"Problematic resources: {list(global_problematic_resources)[:10]}...")

    except Exception as e:
        logger.error(f"Error in main tagging process: {str(e)}")
        raise

def filter_problematic_resources(resources: List[str], known_problematic: Set[str]) -> List[str]:
    """
    Filter out resources that are known to have tagging issues
    """
    filtered = []
    excluded_patterns = [
        # ENIs that might be ephemeral
        r":network-interface/eni-",
        # KMS resources often have permission issues
        r":key/[a-f0-9-]+$",
        # AWS managed/default resources
        r":capacity-provider/FARGATE",
        r":capacity-provider/FARGATE_SPOT",
        r"rule/AWS",  # AWS managed rules (Control Tower, etc.)
        r":user/service-account/",  # Service accounts
        r":datacatalog/AwsDataCatalog",  # Athena data catalogs
        r":backup/backup-vault/aws/", # AWS managed backup vaults
        r":cloudwatch::alarm:AWS_", # AWS managed CloudWatch alarms
        r":log-group:/aws/", # AWS managed log groups
        r":log-group:AWS/", # AWS managed log groups
    ]
    
    for arn in resources:
        # Skip if already in known problematic list
        if arn in known_problematic:
            continue
            
        # Skip if matches any excluded pattern
        if any(re.search(pattern, arn) for pattern in excluded_patterns):
            continue
            
        filtered.append(arn)
    
    skipped = len(resources) - len(filtered)
    if skipped > 0:
        logger.info(f"Filtered out {skipped} potentially problematic resources")
        
    return filtered

def tag_resources_in_chunks(aws_resource_tagging_client, resource_arns_to_tag, desired_tags, TAG_RESOURCES_CHUNK_SIZE):
    """
    Tag resources in chunks with better error handling and tracking
    
    Returns:
        Set[str]: Set of problematic resources that should be excluded in future runs
    """
    max_retries = 2  # Maximum number of retries for each chunk
    base_sleep_time = 2  # Base sleep time in seconds
    problematic_resources = set()
    
    # Convert all desired tags to strings
    string_tags = {k: str(v) for k, v in desired_tags.items()}

    # Process resources in chunks
    for count in range(0, len(resource_arns_to_tag), TAG_RESOURCES_CHUNK_SIZE):
        # Get a chunk and remove duplicates
        chunk = list(set(resource_arns_to_tag[count : count + TAG_RESOURCES_CHUNK_SIZE]))
        logger.info(f"Processing chunk {count//TAG_RESOURCES_CHUNK_SIZE + 1}/{(len(resource_arns_to_tag) + TAG_RESOURCES_CHUNK_SIZE - 1)//TAG_RESOURCES_CHUNK_SIZE} ({len(chunk)} resources)")
        
        # Try tagging with retries and exponential backoff
        for attempt in range(max_retries):
            try:
                # Call the tag_resources API for the current chunk
                res = aws_resource_tagging_client.tag_resources(
                    ResourceARNList=chunk,
                    Tags=string_tags
                )
                
                # Handle failed resources
                if "FailedResourcesMap" in res and res["FailedResourcesMap"]:
                    failed_resources = res["FailedResourcesMap"]
                    logger.warning(f"Failed to tag {len(failed_resources)} resources on attempt {attempt + 1}")
                    
                    # Categorize failures
                    retriable_resources = []
                    for arn, failure in failed_resources.items():
                        error_code = failure.get('ErrorCode', '')
                        error_message = failure.get('ErrorMessage', '')
                        
                        # Add to problematic resources for permanent exclusion
                        if any(pattern in error_code or pattern in error_message for pattern in 
                              ['NotFound', 'AccessDenied', 'InvalidParameter', 'Validation', 'NotAuthorized']):
                            logger.debug(f"Permanently excluding problematic resource: {arn} due to {error_code}: {error_message}")
                            problematic_resources.add(arn)
                        else:
                            # These might be temporary failures
                            retriable_resources.append(arn)
                            
                    # Retry only retriable resources
                    if retriable_resources and attempt < max_retries - 1:
                        logger.info(f"Will retry {len(retriable_resources)} resources after backoff")
                        chunk = retriable_resources
                        # Exponential backoff: 2, 4, 8, 16... seconds
                        sleep_time = base_sleep_time * (2 ** attempt)
                        logger.info(f"Backing off for {sleep_time} seconds before retry")
                        time.sleep(sleep_time)
                        continue
                
                # Break out of retry loop if successful or if no retriable resources
                break
                
            except Exception as e:
                logger.error(f"Error during tagging operation: {str(e)}")
                if attempt < max_retries - 1:
                    # Exponential backoff: 2, 4, 8, 16... seconds
                    sleep_time = base_sleep_time * (2 ** attempt)
                    logger.info(f"Backing off for {sleep_time} seconds before retry")
                    time.sleep(sleep_time)
                else:
                    logger.error(f"Max retries exceeded for chunk, marking resources as problematic")
                    # Mark all resources in this chunk as problematic
                    problematic_resources.update(chunk)
    
    logger.info(f"Tagging complete. Identified {len(problematic_resources)} problematic resources.")
    return problematic_resources

def parse_key_value_string(kv_string: str) -> dict:
    """
    Parse a string of format 'key=value1,key2=value2' into a dictionary
    
    Args:
        kv_string (str): String in format 'key=value1,key2=value2'
        
    Returns:
        dict: Dictionary of key-value pairs
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

def get_search_query_string(desired_tags) -> str:
    """
    Build a search query string for Resource Explorer with improved exclusions
    """
    # Determine if we're restricting to a specific region
    if not bool(os.getenv("GLOBAL", "false")):
        search_query_string = ""
    else:
        search_query_string = f"region:{os.environ['AWS_REGION']} "
    
    # Add tag conditions
    for key, value in desired_tags.items():
        search_query_string += f"-tag:{key}={value} "
    
    # Add resourcetype.supports:tags to find only taggable resources 
    search_query_string += f"resourcetype.supports:tags "
    
    # Exclude resources that typically cause issues with tagging
    search_query_string += "-service:cloudformation "
    search_query_string += "-service:lambda "  # Lambda functions are usually managed by other tools
    search_query_string += "-service:backup backup-vault/aws "  # Exclude AWS managed backup vaults
    search_query_string += "-service:logs log-group:/aws "  # Exclude AWS managed log groups
    
    return search_query_string

def get_results(client, query_string, view_arn):
    """
    Search for resources using ResourceExplorer with better error handling and pagination
    """
    try:
        re_search_paginator = client.get_paginator("search")
        resource_arns_to_tag = []
        
        # Set up pagination parameters
        pagination_config = {
            'MaxItems': 10000,  # Reasonable limit to avoid resource issues
            'PageSize': 100     # Get 100 resources per page
        }
        
        for page_number, page in enumerate(
            re_search_paginator.paginate(
                ViewArn=view_arn, 
                QueryString=query_string,
                PaginationConfig=pagination_config
            ), 1
        ):
            if 'Resources' in page:
                for aws_resource in page["Resources"]:
                    if 'Arn' in aws_resource:
                        resource_arns_to_tag.append(aws_resource["Arn"])
            
            # Log progress
            if page_number % 10 == 0:
                logger.info(f"Processed {page_number} pages, found {len(resource_arns_to_tag)} resources so far")
                
        return resource_arns_to_tag
        
    except Exception as e:
        logger.error(f"Error searching for resources: {str(e)}")
        raise

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
                logger.warning(f"Invalid service format '{service}', skipping")
                continue

            service_parts = service.split(delimiter)
            if len(service_parts) != 2:
                logger.warning(f"Invalid service format '{service}', skipping")
                continue

            services.append(service)

        return services

    except Exception as e:
        logger.error(f"Error parsing service string: {str(e)}")
        return []

# Get environment variables with improved error handling
try:
    desired_tags: Dict[str, str] = parse_key_value_string(os.environ.get("RESOURCE_TAGS", ""))
    resources: List[str] = parse_comma_separated_list_with_validation(os.getenv("RESOURCES", '["*"]'), ":", False)
    ou_ids: List[str] = os.environ.get("OU_IDS", "").split(",") if os.environ.get("OU_IDS") else []
    tag_all_available_resources = resources == ["*"]
    
    # Validate required environment variables
    if not desired_tags:
        logger.warning("No RESOURCE_TAGS defined, tagging will have no effect")
    
    if not ou_ids:
        logger.warning("No OU_IDS defined, no accounts will be processed")
except Exception as e:
    logger.error(f"Error initializing environment variables: {str(e)}")
    desired_tags = {}
    resources = ["*"]
    ou_ids = []
    tag_all_available_resources = True

def lambda_handler(event, context):
    """
    Main Lambda handler with improved logging and error handling
    """
    start_time = time.time()
    logger.info(f"Starting auto-tagging process with event: {event}")
    
    # Configuration
    TAG_RESOURCES_CHUNK_SIZE = int(os.getenv("TAG_RESOURCES_CHUNK_SIZE", "5"))
    
    try:
        # Validate required configuration
        if not ACCOUNTS_ROLE:
            raise ValueError("ACCOUNTS_ROLE_NAME environment variable is required")
            
        if not ou_ids:
            raise ValueError("OU_IDS environment variable is required")
            
        if not desired_tags:
            raise ValueError("RESOURCE_TAGS environment variable is required")
        
        # Log configuration details
        logger.info(f"Configuration: TAG_RESOURCES_CHUNK_SIZE={TAG_RESOURCES_CHUNK_SIZE}, ACCOUNTS_ROLE={ACCOUNTS_ROLE}")
        logger.info(f"Target OUs: {ou_ids}")
        logger.info(f"Target resource types: {resources}")
        logger.info(f"Applying tags: {desired_tags}")
        
        # Tag resources for all accounts in the specified OUs
        tag_resources_for_ous(ou_ids, desired_tags, TAG_RESOURCES_CHUNK_SIZE)
        
        # Log completion
        elapsed_time = time.time() - start_time
        logger.info(f"Auto-tagging process completed successfully in {elapsed_time:.2f} seconds")
        
        return {
            'statusCode': 200,
            'body': 'Auto-tagging process completed successfully'
        }
        
    except Exception as e:
        # Log error and return failure
        elapsed_time = time.time() - start_time
        logger.error(f"Auto-tagging process failed after {elapsed_time:.2f} seconds: {str(e)}")
        
        return {
            'statusCode': 500,
            'body': f'Auto-tagging process failed: {str(e)}'
        }