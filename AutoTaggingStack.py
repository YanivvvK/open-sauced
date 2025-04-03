from aws_cdk import (
    Stack,
    CfnParameter,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_cloudformation as cfn,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

class AutoTaggingStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Define parameters
        resource_prefix = CfnParameter(
            self, "ResourcePrefix",
            default="aws-controltower",
            description="Prefix to be added to resources created by this template."
        )

        solution_installation_id = CfnParameter(
            self, "SolutionInstallationID",
            default="allCloud",
            description="Solution ID to append to each resource name."
        )

        resources = CfnParameter(
            self, "Resources",
            default="*",
            allowed_pattern="^\\*|[a-zA-Z0-9]+:[a-zA-Z0-9]+(?:,[a-zA-Z0-9]+:[a-zA-Z0-9]+)*$",
            constraint_description="Must be service:resource or comma-separated list. Example: sns:topic or sns:topic,sqs:queue",
            description="List of resources to tag provided as service:resource or comma-separated list. Example: \"sns:topic,sqs:queue\""
        )
        
        # Instead of using the ResourceTags parameter, we're hardcoding it as requested
        resource_tags = "map-migrated=mig6GD6I31OYX"

        global_region = CfnParameter(
            self, "GlobalRegion",
            default="false",
            allowed_values=["true", "false"],
            description="If the tagging should happen in the stack region or in all regions."
        )

        propagate_account_tags = CfnParameter(
            self, "PropagateAccountTags",
            default="false",
            allowed_values=["true", "false"],
            description="If the process should propagate the AWS account tags to discovered resources."
        )

        full_scan_interval_hours = CfnParameter(
            self, "FullScanIntervalHours",
            default=24,
            description="FullScanIntervalHours",
            max_value=24,
            min_value=1
        )

        log_level = CfnParameter(
            self, "LogLevel",
            default="INFO",
            allowed_values=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
            description="Log Level for development and debugging."
        )

        # Create IAM role for the Lambda function
        auto_tagging_function_role = iam.Role(
            self, "AutoTaggingFunctionServiceRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )

        # Add tagging permissions policy to the role
        auto_tagging_function_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "application-autoscaling:ListTagsForResource",
                    "application-autoscaling:TagResource",
                    "application-autoscaling:UntagResource",
                    "applicationinsights:ListTagsForResource",
                    "autoscaling:CreateOrUpdateTags",
                    "autoscaling:DeleteTags",
                    "autoscaling:DescribeTags",
                    "cloudfront:ListTagsForResource",
                    "cloudfront:TagResource",
                    "cloudfront:UntagResource",
                    "cloudwatch:ListTagsForResource",
                    "cloudwatch:TagResource",
                    "cloudwatch:UntagResource",
                    "dax:ListTags",
                    "dax:TagResource",
                    "dax:UntagResource",
                    "dynamodb:ListTagsOfResource",
                    "dynamodb:TagResource",
                    "dynamodb:UntagResource",
                    "ec2:CreateTags",
                    "ec2:DeleteTags",
                    "ec2:DescribeTags",
                    "ecr-public:TagResource",
                    "ecr-public:UntagResource",
                    "ecr:TagResource",
                    "ecr:UntagResource",
                    "ecs:ListTagsForResource",
                    "ecs:TagResource",
                    "ecs:UntagResource",
                    "eks:ListTagsForResource",
                    "eks:TagResource",
                    "eks:UntagResource",
                    "elasticache:AddTagsToResource",
                    "elasticache:ListTagsForResource",
                    "elasticache:RemoveTagsFromResource",
                    "elasticbeanstalk:AddTags",
                    "elasticbeanstalk:ListTagsForResource",
                    "elasticbeanstalk:RemoveTags",
                    "elasticbeanstalk:UpdateTagsForResource",
                    "elasticfilesystem:CreateTags",
                    "elasticfilesystem:DeleteTags",
                    "elasticfilesystem:DescribeTags",
                    "elasticfilesystem:ListTagsForResource",
                    "elasticfilesystem:TagResource",
                    "elasticfilesystem:UntagResource",
                    "elasticloadbalancing:AddTags",
                    "elasticloadbalancing:DescribeTags",
                    "elasticloadbalancing:RemoveTags",
                    "elasticmapreduce:AddTags",
                    "elasticmapreduce:RemoveTags",
                    "emr-containers:ListTagsForResource",
                    "emr-containers:TagResource",
                    "emr-containers:UntagResource",
                    "emr-serverless:ListTagsForResource",
                    "emr-serverless:TagResource",
                    "emr-serverless:UntagResource",
                    "events:ListTagsForResource",
                    "events:TagResource",
                    "events:UntagResource",
                    "evidently:ListTagsForResource",
                    "evidently:TagResource",
                    "evidently:UntagResource",
                    "glue:GetTags",
                    "glue:TagResource",
                    "glue:UntagResource",
                    "iam:ListInstanceProfileTags",
                    "iam:ListMFADeviceTags",
                    "iam:ListOpenIDConnectProviderTags",
                    "iam:ListPolicyTags",
                    "iam:ListRoleTags",
                    "iam:ListSAMLProviderTags",
                    "iam:ListServerCertificateTags",
                    "iam:ListUserTags",
                    "iam:TagInstanceProfile",
                    "iam:TagMFADevice",
                    "iam:TagOpenIDConnectProvider",
                    "iam:TagPolicy",
                    "iam:TagRole",
                    "iam:TagSAMLProvider",
                    "iam:TagServerCertificate",
                    "iam:TagUser",
                    "iam:UntagInstanceProfile",
                    "iam:UntagMFADevice",
                    "iam:UntagOpenIDConnectProvider",
                    "iam:UntagPolicy",
                    "iam:UntagRole",
                    "iam:UntagSAMLProvider",
                    "iam:UntagServerCertificate",
                    "iam:UntagUser",
                    "iotevents:ListTagsForResource",
                    "iotevents:TagResource",
                    "iotevents:UntagResource",
                    "kinesis:AddTagsToStream",
                    "kinesis:ListTagsForStream",
                    "kinesis:RemoveTagsFromStream",
                    "kinesisanalytics:ListTagsForResource",
                    "kinesisanalytics:TagResource",
                    "kinesisanalytics:UntagResource",
                    "kinesisvideo:ListTagsForResource",
                    "kinesisvideo:ListTagsForStream",
                    "kinesisvideo:TagResource",
                    "kinesisvideo:TagStream",
                    "kinesisvideo:UntagResource",
                    "kinesisvideo:UntagStream",
                    "kms:ListResourceTags",
                    "kms:TagResource",
                    "kms:UntagResource",
                    "logs:ListTagsForResource",
                    "logs:ListTagsLogGroup",
                    "logs:TagLogGroup",
                    "logs:TagResource",
                    "logs:UntagLogGroup",
                    "logs:UntagResource",
                    "mediaconnect:ListTagsForResource",
                    "mediaconnect:TagResource",
                    "mediaconnect:UntagResource",
                    "organizations:DescribeOrganization",
                    "organizations:ListTagsForResource",
                    "pipes:ListTagsForResource",
                    "pipes:TagResource",
                    "pipes:UntagResource",
                    "rds:AddTagsToResource",
                    "rds:ListTagsForResource",
                    "rds:RemoveTagsFromResource",
                    "resource-explorer-2:CreateIndex",
                    "resource-explorer-2:CreateView",
                    "resource-explorer-2:DeleteIndex",
                    "resource-explorer-2:DeleteView",
                    "resource-explorer-2:GetDefaultView",
                    "resource-explorer-2:GetIndex",
                    "resource-explorer-2:GetView",
                    "resource-explorer-2:ListIndexes",
                    "resource-explorer-2:ListTagsForResource",
                    "resource-explorer-2:ListViews",
                    "resource-explorer-2:Search",
                    "resource-explorer-2:TagResource",
                    "resource-explorer-2:UntagResource",
                    "resourcegroupstaggingapi:GetResources",
                    "resourcegroupstaggingapi:TagResources",
                    "resourcegroupstaggingapi:UntagResources",
                    "rum:ListTagsForResource",
                    "rum:TagResource",
                    "rum:UntagResource",
                    "s3:GetBucketTagging",
                    "s3:ListTagsForResource",
                    "s3:PutBucketTagging",
                    "s3:ReplicateTags",
                    "s3:TagResource",
                    "s3:UntagResource",
                    "sagemaker-geospatial:ListTagsForResource",
                    "sagemaker-geospatial:TagResource",
                    "sagemaker-geospatial:UntagResource",
                    "sagemaker:AddTags",
                    "sagemaker:DeleteTags",
                    "sagemaker:ListTags",
                    "scheduler:ListTagsForResource",
                    "scheduler:TagResource",
                    "scheduler:UntagResource",
                    "schemas:ListTagsForResource",
                    "schemas:TagResource",
                    "schemas:UntagResource",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:TagResource",
                    "secretsmanager:UntagResource",
                    "sns:ListTagsForResource",
                    "sns:TagResource",
                    "sns:UntagResource",
                    "sqs:ListQueueTags",
                    "sqs:TagQueue",
                    "sqs:UntagQueue",
                    "ssm:AddTagsToResource",
                    "ssm:ListTagsForResource",
                    "ssm:RemoveTagsFromResource",
                    "states:ListTagsForResource",
                    "states:TagResource",
                    "states:UntagResource",
                    "storagegateway:AddTagsToResource",
                    "storagegateway:ListTagsForResource",
                    "storagegateway:RemoveTagsFromResource",
                    "sts:GetCallerIdentity",
                    "swf:ListTagsForResource",
                    "swf:TagResource",
                    "swf:UntagResource",
                    "synthetics:ListTagsForResource",
                    "synthetics:TagResource",
                    "synthetics:UntagResource",
                    "tag:GetResources",
                    "tag:TagResources",
                    "tag:UntagResources",
                    "transfer:ListTagsForResource",
                    "transfer:TagResource",
                    "transfer:UntagResource",
                    "waf-regional:ListTagsForResource",
                    "waf-regional:TagResource",
                    "waf-regional:UntagResource",
                    "waf:ListTagsForResource",
                    "waf:TagResource",
                    "waf:UntagResource",
                    "wafv2:ListTagsForResource",
                    "wafv2:TagResource",
                    "wafv2:UntagResource",
                    "workspaces:CreateTags",
                    "workspaces:DeleteTags",
                    "workspaces:DescribeTags",
                    "xray:ListTagsForResource",
                    "xray:TagResource",
                    "xray:UntagResource"
                ],
                resources=["*"],
                effect=iam.Effect.ALLOW
            )
        )

        # Lambda function code for auto tagging
        auto_tagging_function_code = '''
import os
from typing import Dict, List, Optional
import boto3
import logging
# TAG_RESOURCES_CHUNK_SIZE = 20

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
    return search_query_string

def get_results(client, query_string, view_arn):
    re_search_paginator = client.get_paginator("search")
    resource_arns_to_tag = []
    for page in re_search_paginator.paginate(
        ViewArn=view_arn,
        QueryString=query_string,
    ):
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
def get_current_account_id() -> str:
    """
    Get the current AWS account ID
    
    Returns:
        str: AWS Account ID
    """
    try:
        sts_client = boto3.client('sts')
        return sts_client.get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Error getting current account ID: {str(e)}")
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

logger = logging.getLogger()
loglevel = os.getenv("LOG_LEVEL", "INFO")  # Set to DEBUG for detailed logging
logger.setLevel(loglevel)
desired_tags: Dict[str, str] = parse_key_value_string(os.environ["RESOURCE_TAGS"])
resources: List[str] = parse_comma_separated_list_with_validation(os.getenv("RESOURCES", '["*"]'), ":", False)
tag_all_available_resources = resources == ["*"]

def lambda_handler(event, context) -> None:
    # global TAG_RESOURCES_CHUNK_SIZE
    TAG_RESOURCES_CHUNK_SIZE = 20
    aws_resource_tagging_client = boto3.client("resourcegroupstaggingapi")
    resource_explorer_client = boto3.client("resource-explorer-2")

    if os.getenv("PROPAGATE_ACCOUNT_TAGS", "false").lower() == "true":
        try:
            logger.info("Attempting to get current account ID")
            account_id = get_current_account_id()
            logger.info(f"Current account ID: {account_id}")
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
        create_view_command_output = resource_explorer_client.create_view(
            ViewName="AutoTaggingView", IncludedProperties=[{"Name": "tags"}]
        )
        view_arn = create_view_command_output["View"]["ViewArn"]
    except Exception as e:
        logger.info(f"Exception occurred: {str(e)}")
        logger.info("Failed to create new resource explorer view, attempting to import the solution-managed view")
        list_view_command_output = resource_explorer_client.list_views()
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
            resource_explorer_client, tag_search_query_string, view_arn
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
                    resource_explorer_client,
                    f"{resource_type_search_query_string} {tag_search_query_string}",
                    view_arn,
                )
            )
    logger.info(
        f"Found {len(resource_arns_to_tag)} resources that should be tagged using the following tags: {desired_tags}"
    )
    logger.info(f"TAG_RESOURCES_CHUNK_SIZE: {TAG_RESOURCES_CHUNK_SIZE}")
    logger.info(f"Resource ARNs to tag: {resource_arns_to_tag}")
    if resource_arns_to_tag:
        logger.info(f"Start tagging resources using AWS Resource Tagging API")
        for count in range(0, len(resource_arns_to_tag), TAG_RESOURCES_CHUNK_SIZE):
            
            try:
                res = aws_resource_tagging_client.tag_resources(
                    ResourceARNList=list(
                        set(resource_arns_to_tag[
                        count : count + TAG_RESOURCES_CHUNK_SIZE
                    ])
                    ),
                    Tags=desired_tags,
                )
                logger.info(res)
                if "FailedResourcesMap" in res and len(res["FailedResourcesMap"]) > 0:
                    for resource_arn, failed_info in res["FailedResourcesMap"].items():
                        logger.error(
                            f"Failed to tag resource: {resource_arn}, "
                            + f"Info: {failed_info}"
                        )
            except Exception as e:
                logger.error(f"Failure in tagging operation, detailed error: {e}.")
                
    try:                
        resource_explorer_client.delete_view(ViewArn=view_arn)
    except Exception as e:
        logger.error(f"Failed to delete view: {view_arn}")
'''

        # Create Lambda function for auto tagging
        auto_tagging_function = lambda_.Function(
            self, "AutoTaggingFunction",
            function_name=f"{resource_prefix.value_as_string}-auto-tagging-{solution_installation_id.value_as_string}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.lambda_handler",
            code=lambda_.Code.from_inline(auto_tagging_function_code),
            timeout=Duration.seconds(900),
            memory_size=256,
            environment={
                "RESOURCES": resources.value_as_string,
                "RESOURCE_TAGS": resource_tags,  # Using our hardcoded value
                "GLOBAL": global_region.value_as_string,
                "PROPAGATE_ACCOUNT_TAGS": propagate_account_tags.value_as_string,
                "LOG_LEVEL": log_level.value_as_string
            },
            role=auto_tagging_function_role
        )

        # Create Resource Explorer Index Custom Resource function role
        get_or_create_resource_explorer_index_function_role = iam.Role(
            self, "GetOrCreateResourceExplorerIndexFunctionServiceRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )

        # Add permissions for Resource Explorer
        get_or_create_resource_explorer_index_function_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "resource-explorer-2:CreateIndex",
                    "resource-explorer-2:DeleteIndex",
                    "resource-explorer-2:GetDefaultView",
                    "resource-explorer-2:GetIndex",
                    "resource-explorer-2:GetView",
                    "resource-explorer-2:ListIndexes",
                    "resource-explorer-2:ListTagsForResource",
                    "resource-explorer-2:ListViews",
                    "resource-explorer-2:Search"
                ],
                resources=["*"],
                effect=iam.Effect.ALLOW
            )
        )

        # Add permissions for creating service-linked role
        get_or_create_resource_explorer_index_function_role.add_to_policy(
            iam.PolicyStatement(
                actions=["iam:CreateServiceLinkedRole"],
                resources=[f"arn:{self.partition}:iam::{self.account}:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer"],
                effect=iam.Effect.ALLOW,
                conditions={
                    "StringLike": {
                        "iam:AWSServiceName": "resource-explorer-2.amazonaws.com"
                    }
                }
            )
        )

        # Add permissions for attaching policies to the service-linked role
        get_or_create_resource_explorer_index_function_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:AttachRolePolicy",
                    "iam:PutRolePolicy"
                ],
                resources=[f"arn:{self.partition}:iam::{self.account}:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer"],
                effect=iam.Effect.ALLOW
            )
        )

        # Lambda function code for Resource Explorer Index Custom Resource
        get_or_create_resource_explorer_index_function_code = '''
from typing import Optional
import urllib3
import json
import logging
import boto3
from botocore.config import Config
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

config = Config(retries={"max_attempts": 10, "mode": "standard"})
resource_explorer_client = boto3.client("resource-explorer-2")


class cfnresponse:
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

    @classmethod
    def send(
        cls,
        event,
        context,
        responseStatus,
        responseData,
        physicalResourceId=None,
        noEcho=False,
        reason=None,
    ):
        _http = urllib3.PoolManager()
        responseUrl = event["ResponseURL"]
        responseBody = {
            "Status": responseStatus,
            "Reason": reason
            or "See the details in CloudWatch Log Stream: {}".format(
                context.log_stream_name
            ),
            "PhysicalResourceId": physicalResourceId or context.log_stream_name,
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": noEcho,
            "Data": responseData,
        }
        json_responseBody = json.dumps(responseBody)
        headers = {"content-type": "", "content-length": str(len(json_responseBody))}
        try:
            response = _http.request(
                "PUT", responseUrl, headers=headers, body=json_responseBody
            )
            logger.info(f"Status code: {response.status}")
        except Exception as e:
            logger.info(f"send(..) failed executing http.request(..):{str(e)}")


def try_to_get_index() -> Optional[str]:
    try:
        list_indexes_command_output = resource_explorer_client.list_indexes(
            Regions=[os.environ["AWS_REGION"]]
        )
        if "Indexes" in list_indexes_command_output:
            for index_details in list_indexes_command_output["Indexes"]:
                if index_details["Type"] == "LOCAL":
                    return index_details["Arn"]
        return None
    except:
        return None


def delete_index(index_arn: str) -> None:
    resource_explorer_client.delete_index(Arn=index_arn)


def create_index() -> str:
    create_index_command_output = resource_explorer_client.create_index()
    return create_index_command_output["Arn"]


def lambda_handler(event, context):
    logger.info(f"event: {event}")
    response = {}
    try:
        logger.info("try to get local index")
        index_arn = try_to_get_index()
        logger.info(f"index_arn: {index_arn}")
        if event["RequestType"] == "Delete":
            if index_arn:
                logger.info("try to delete local index")
                delete_index(index_arn)
        else:
            if not index_arn:
                logger.info("try to create local index")
                index_arn = create_index()
                logger.info(f"index_arn: {index_arn}")
        cfnresponse.send(
            event,
            context,
            cfnresponse.SUCCESS,
            response,
            "GetOrCreateResourceExplorerIndexCustomResource",
        )
    except Exception as err:
        logger.exception(f"error: {str(err)}")
        response["error"] = str(err)
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            response,
            "GetOrCreateResourceExplorerIndexCustomResource",
        )
'''

        # Create Lambda function for Resource Explorer Index Custom Resource
        get_or_create_resource_explorer_index_function = lambda_.Function(
            self, "GetOrCreateResourceExplorerIndexFunction",
            function_name=f"{resource_prefix.value_as_string}-re-index-cr-{solution_installation_id.value_as_string}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.lambda_handler",
            code=lambda_.Code.from_inline(get_or_create_resource_explorer_index_function_code),
            timeout=Duration.seconds(180),
            memory_size=128,
            environment={
                "LOG_LEVEL": log_level.value_as_string
            },
            role=get_or_create_resource_explorer_index_function_role
        )

        # Create Custom Resource for Resource Explorer Index
        get_or_create_resource_explorer_index_cr = cfn.CustomResource(
            self, "GetOrCreateResourceExplorerIndexCR",
            service_token=get_or_create_resource_explorer_index_function.function_arn,
            properties={
                "ServiceTimeout": "180"
            },
            removal_policy=RemovalPolicy.DELETE
        )

        # Create EventBridge Rule to trigger the auto tagging function
        auto_tagging_interval_trigger = events.Rule(
            self, "AutoTaggingIntervalTrigger",
            rule_name=f"{resource_prefix.value_as_string}-auto-tagging-{solution_installation_id.value_as_string}",
            schedule=events.Schedule.rate(Duration.hours(full_scan_interval_hours.value_as_number)),
            targets=[
                targets.LambdaFunction(auto_tagging_function)
            ],
            enabled=True
        )

        # Add dependency to ensure Resource Explorer Index is created before the event rule
        auto_tagging_interval_trigger.node.add_dependency(get_or_create_resource_explorer_index_cr)