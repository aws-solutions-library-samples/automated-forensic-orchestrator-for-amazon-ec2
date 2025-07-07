#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os

from aws_xray_sdk.core import xray_recorder

from ..common.aws_utils import resolve_artifact_metadata
from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.exception import (
    ForensicLambdaExecutionException,
    MemoryAcquisitionError,
)
from ..common.log import get_logger
from ..data.datatypes import (
    ArtifactCategory,
    ArtifactStatus,
    ArtifactType,
    ForensicsProcessingPhase,
)
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Check Memory Acquisition")
def handler(event, context):
    logger.info("Got event{}".format(event))
    s3_bucket_name = os.environ["S3_BUCKET_NAME"]
    s3_client = create_aws_client("s3")
    input_body = event["Payload"]["body"]
    output_body = input_body.copy()
    app_account_region = input_body.get("instanceRegion")
    forensic_type = input_body["forensicType"]

    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=(
            True
            if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
            else False
        ),
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )
    try:

        app_account_id = input_body.get("instanceAccount")
        current_account = context.invoked_function_arn.split(":")[4]

        app_account_role = os.environ["APP_ACCOUNT_ROLE"]
        ssm_client = create_aws_client(
            "ssm",
            current_account=current_account,
            target_account=app_account_id,
            target_region=app_account_region,
            app_account_role=app_account_role,
        )

        # code starts here.
        forensic_id = input_body["forensicId"]
        for instance_id in input_body["ForensicInstanceIds"]:
            instance_memory_details = input_body["InstanceResults"][
                instance_id
            ]
            logger.info(instance_memory_details)
            command_id = instance_memory_details["MemoryAcquisition"][
                "CommandId"
            ]
            command_id_artifact_map = instance_memory_details[
                "MemoryAcquisition"
            ]["CommandIdArtifactMap"]
            prefix = command_id_artifact_map[command_id]["Prefix"]
            ssm_document_name = command_id_artifact_map[command_id][
                "SSMDocumentName"
            ]
            logger.info("Got CommandId {}".format(command_id))
            logger.info("Got ForensicInstanceId {}".format(instance_id))
            ssm_response = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            if ssm_response.get("StatusDetails", None) in [
                "Pending",
                "Delayed",
                "InProgress",
            ]:
                output_body["InstanceResults"][instance_id][
                    "isMemoryAcquisitionComplete"
                ] = False
            elif ssm_response.get("StatusDetails", None) == "Success":
                output_body["InstanceResults"][instance_id][
                    "isMemoryAcquisitionComplete"
                ] = True
                artifact_metadata = resolve_artifact_metadata(
                    s3_client, s3_bucket_name, prefix
                )
                if not artifact_metadata:
                    raise ForensicLambdaExecutionException(
                        "Job execution failed. SSM command succeeded however memory output was not uploaded."
                    )
                artifact_id = fds.create_forensic_artifact(
                    id=forensic_id,
                    phase=ForensicsProcessingPhase.ACQUISITION,
                    category=ArtifactCategory.MEMORY,
                    type=ArtifactType.MEMORYDUMP,
                    status=ArtifactStatus.SUCCESS,
                    component_id="checkMemoryAcquisition",
                    component_type="Lambda",
                    ssm_document_name=ssm_document_name,
                    ssm_command_id=command_id,
                    artifact_location=artifact_metadata[0].get(
                        "artifact_location"
                    ),
                    artifact_size=artifact_metadata[0].get("artifact_size"),
                    artifact_SHA256=artifact_metadata[0].get("sha256"),
                )
                output_body["InstanceResults"][instance_id][
                    "MemoryAcquisition"
                ]["CommandInputArtifactId"] = artifact_id

            elif ssm_response.get("StatusDetails", None) not in ["Success"]:
                raise ForensicLambdaExecutionException(
                    "Job execution failed. {}".format(
                        ssm_response.get("StatusDetails", None)
                    )
                )
        logger.info(f"The output body is {output_body}")
        overall_instance_memory_acquisition_status = []
        for instance_id in output_body["ForensicInstanceIds"]:
            overall_instance_memory_acquisition_status.append(
                output_body["InstanceResults"][instance_id][
                    "isMemoryAcquisitionComplete"
                ]
            )
        # check if all the list elements are True
        if all(overall_instance_memory_acquisition_status):
            output_body["isMemoryAcquisitionComplete"] = "TRUE"
            memory_acquisition_document_name = os.environ[
                "LINUX_LIME_MEMORY_ACQUISITION"
            ]
            windows_memory_acquisition_document_name = os.environ[
                "WINDOWS_LIME_MEMORY_ACQUISITION"
            ]

            if "clusterInfo" in input_body:
                platform_details = input_body.get("instanceInfo")[0].get(
                    "PlatformDetails"
                )
            else:
                platform_details = input_body.get("instanceInfo").get(
                    "PlatformDetails"
                )

            if platform_details == "Windows":
                memory_acquisition_document_name = (
                    windows_memory_acquisition_document_name
                )
            ssm_client_current_account = create_aws_client("ssm")
            ssm_client_current_account.modify_document_permission(
                Name=memory_acquisition_document_name,
                PermissionType="Share",
                AccountIdsToRemove=[app_account_id],
            )
        else:
            output_body["isMemoryAcquisitionComplete"] = "FALSE"
        # code ends here.
        return create_response(200, output_body)

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)

        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }

        logger.error(exception_obj)

        output_body["errorName"] = "Error: checking memory dump status"
        output_body["errorDescription"] = (
            f"Error while performing Forensic {forensic_type} acquisition - memory dump check"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "checkMemoryAcquisition"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise MemoryAcquisitionError(output_body)
