from aws_cdk import (
    Stack,
    aws_cloudformation as cloudformation,
    aws_servicecatalog as servicecatalog,
    Aws,
)
from stacks.CreateTagRoleStack import CreateTagRoleStack
from constructs import Construct


class TagRoleStackSet(Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        ou_ids: list[str],
        integration_id: str,
        stack_name: str,
        **kwargs,
    ) -> None:

        super().__init__(scope, id, **kwargs)

        #########################################################
        ##### Stack Set to deploy the Role for all accounts #####
        #########################################################

        deployment_product = CreateTagRoleStack(
            self,
            id=f"ChildISetup{stack_name}",
            integration_account_id = integration_id
        )
        cfn_template: servicecatalog.CloudFormationTemplate = (
            servicecatalog.CloudFormationTemplate.from_product_stack(deployment_product)
            .bind(self)
            .http_url
        )

        cloudformation.CfnStackSet(
            self,
            id=f"{stack_name}StackSet",
            stack_set_name=f"{stack_name}-roles",
            permission_model="SERVICE_MANAGED",
            capabilities=["CAPABILITY_NAMED_IAM"],
            call_as="DELEGATED_ADMIN",
            stack_instances_group=[
                cloudformation.CfnStackSet.StackInstancesProperty(
                    deployment_targets=cloudformation.CfnStackSet.DeploymentTargetsProperty(
                        organizational_unit_ids=ou_ids,
                        account_filter_type="NONE",
                    ),
                    regions=[Aws.REGION],
                ),
            ],
            auto_deployment=cloudformation.CfnStackSet.AutoDeploymentProperty(
                enabled=True, retain_stacks_on_account_removal=False
            ),
            template_url=cfn_template,
        )