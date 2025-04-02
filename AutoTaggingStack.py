from aws_cdk import (
    Stack,
    CfnParameter,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    Duration,
)
from constructs import Construct
from config.config import config

class AutoTaggingStack(Stack):
    def __init__(self, scope: Construct, id: str, ou_ids: list[str], **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        solution_installation_id = CfnParameter(
            self, "SolutionInstallationID",
            default="allCloud",
            description="Solution ID to append to each resource name."
        )

        resources = CfnParameter(
            self, "Resources",
            default="*",
            allowed_pattern="^\\*|[a-zA-Z0-9-]+:[a-zA-Z0-9-]+(?:,[a-zA-Z0-9-]+:[a-zA-Z0-9-]+)*$",
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
            min_value=1,
            type="Number"
        )

        log_level = CfnParameter(
            self, "LogLevel",
            default="INFO",
            allowed_values=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
            description="Log Level for development and debugging."
        )

        # policies for the Auto Tagging lambda role
        policy_document = iam.PolicyDocument(
            statements=[         
                iam.PolicyStatement(
                    actions=["organizations:ListAccounts", "organizations:ListTagsForResource", "organizations:ListAccountsForParent", "organizations:ListAccountsForParent", "organizations:ListOrganizationalUnitsForParent"],
                    resources=["*"], 
                    sid="OrganizationsPermissions"  
                ),

                iam.PolicyStatement(
                    actions=["sts:AssumeRole"],
                    resources=["arn:aws:iam::*:role/lz-integration-Accounts-Tag-Role"],  # Replace with your target account and role ARN
                    sid="AssumeRolePermissions"
                ),
            ] )
        
        # role for the shutdown lambda
        auto_tagging_lambda_role = iam.Role(
            self,
            "AutoTaggingLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="lz-integration-AutoTaggingLambdaRole",
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")],
            inline_policies = {"RolePolicy": policy_document}
        ) 

        
        # Create Lambda function for auto tagging
        auto_tagging_function = lambda_.Function(
            self, "AutoTaggingFunction",
            function_name=f"auto-tagging-{solution_installation_id.value_as_string}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="auto_tag_lambda.lambda_handler",
            code=lambda_.Code.from_asset("stacks/assets/lambda_package"),
            timeout=Duration.seconds(900),
            memory_size=256,
            environment={
                "ACCOUNTS_ROLE_NAME": "lz-integration-Accounts-Tag-Role",
                "OU_IDS" : ','.join(ou_ids),
                "RESOURCES": resources.value_as_string,
                "RESOURCE_TAGS": resource_tags,  # Using our hardcoded value
                "GLOBAL": global_region.value_as_string,
                "PROPAGATE_ACCOUNT_TAGS": propagate_account_tags.value_as_string,
                "LOG_LEVEL": log_level.value_as_string
            },
            role=auto_tagging_lambda_role
        )

        # Create EventBridge Rule to trigger the auto tagging function
        auto_tagging_interval_trigger = events.Rule(
            self, "AutoTaggingIntervalTrigger",
            rule_name=f"auto-tagging-{solution_installation_id.value_as_string}",
            schedule=events.Schedule.rate(Duration.hours(full_scan_interval_hours.value_as_number)),
            targets=[
                targets.LambdaFunction(auto_tagging_function)
            ],
            enabled=True
        )
