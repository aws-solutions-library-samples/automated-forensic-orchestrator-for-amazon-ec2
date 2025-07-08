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
import uuid

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import AWSCachedClient, create_aws_client
from ..common.common import clean_date_format, create_response
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)

instance_id = ""

# s3ProfileDownloadURI
# OSProfile

region = os.environ["AWS_REGION"]
s3_bucket_name = os.environ["S3_BUCKET_NAME"]
windows_memory_acquisition_document_name = os.environ[
    "WINDOWS_LIME_MEMORY_LOAD_INVESTIGATION"
]


@xray_recorder.capture("Run Memory Forensics")
def handler(event, _):
    """
    Lambda function handler for performing Memory Forensic Analysis
    """
    input_body = event["Payload"]["body"]

    if "clusterInfo" in input_body:
        for each_instance_id in input_body["ForensicInstanceIds"]:
            for each_instance_info in input_body["instanceInfo"]:
                if each_instance_info["InstanceId"] == each_instance_id:
                    platform_name = each_instance_info["PlatformName"]
                    platform_version = each_instance_info["PlatformVersion"]
                    platform_detail = each_instance_info["PlatformDetails"]
                    break
            output_body = perform_memory_investigation(
                each_instance_id,
                platform_name,
                platform_version,
                platform_detail,
                event,
            )
        return create_response(200, output_body)
    else:
        instance_id = input_body["ForensicInstanceIds"][0]
        platform_name = input_body.get("instanceInfo").get("PlatformName")
        platform_version = input_body.get("instanceInfo").get(
            "PlatformVersion"
        )
        platform_detail = input_body.get("instanceInfo").get("PlatformDetails")
        output_body = perform_memory_investigation(
            instance_id,
            platform_name,
            platform_version,
            platform_detail,
            event,
        )
        return create_response(200, output_body)


def perform_memory_investigation(
    instance_id, platform_name, platform_version, platform_detail, event
):
    if platform_detail == "Windows":
        memory_load_document_name = windows_memory_acquisition_document_name
    elif platform_name == "Red Hat Enterprise Linux":
        if 10 > float(platform_version) > 9:
            rhel_version = "9"
        if 9 > float(platform_version) > 8:
            rhel_version = "8"
        if 8 > float(platform_version) > 7:
            rhel_version = "7"
        memory_load_document_name = os.environ[
            "RHEL" + rhel_version + "_LIME_MEMORY_LOAD_INVESTIGATION"
        ]
    else:
        memory_load_document_name = os.environ[
            "LIME_MEMORY_LOAD_INVESTIGATION"
        ]
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

    # implementation Payload
    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]
    s3_role_arn = os.environ["S3_COPY_ROLE"]
    logger.info(f"The input body is {input_body}")
    input_artifact_id = input_body["InstanceResults"][instance_id][
        "MemoryAcquisition"
    ]["CommandInputArtifactId"]
    forensic_type = input_body["forensicType"]
    output_body = input_body.copy()

    try:

        forensic_investigation_instance_id = input_body[
            "ForensicInvestigationInstanceId"
        ]
        ssm_client = create_aws_client("ssm")

        response = ssm_client.describe_instance_information()

        logger.info(response)

        is_ssm_installed = False

        is_ssm_installed = any(
            item["InstanceId"] == forensic_investigation_instance_id
            for item in response["InstanceInformationList"]
        )

        output_body["forensicId"] = forensic_id
        output_body["ForensicInstanceId"] = instance_id
        output_body["forensicInvestigationInstanceId"] = (
            forensic_investigation_instance_id
        )

        ssm_cmd_artifact_map = {}

        if is_ssm_installed:
            sts = AWSCachedClient(region).get_connection("sts")

            tokens = sts.assume_role(
                RoleArn=s3_role_arn,
                RoleSessionName="{}-s3read-copy".format(str(uuid.uuid4())),
            )["Credentials"]

            params = {
                "AccessKeyId": [tokens["AccessKeyId"]],
                "SecretAccessKey": [tokens["SecretAccessKey"]],
                "SessionToken": [tokens["SessionToken"]],
                "Region": [region],
                "s3DownloadCommands": [
                    "aws s3 cp s3://{0}/memory/{1}/{2} . --recursive".format(
                        s3_bucket_name, instance_id, forensic_id
                    )
                ],
                "s3Bucket": [s3_bucket_name],
                "s3MemoryCaptureKey": [
                    "memory/{0}/{1}".format(instance_id, forensic_id)
                ],
                "s3ProfileBucket": [os.environ["VOLATILITY2_PROFILES_BUCKET"]],
                "s3ProfileLocation": [
                    os.environ["VOLATILITY2_PROFILES_PREFIX"]
                ],
                "forensicID": [forensic_id],
                "s3Location": [
                    "s3://{0}/memory-analysis/{1}/{2}".format(
                        s3_bucket_name, instance_id, forensic_id
                    )
                ],
            }
            response = ssm_client.send_command(
                InstanceIds=[forensic_investigation_instance_id],
                DocumentName=memory_load_document_name,
                Comment="Memory Analysis for " + instance_id,
                Parameters=params,
                CloudWatchOutputConfig={
                    "CloudWatchLogGroupName": forensic_id,
                    "CloudWatchOutputEnabled": True,
                },
            )

            fds.add_forensic_timeline_event(
                id=forensic_id,
                name="Memory Investigation",
                description="Running memory investigation commands",
                phase=ForensicsProcessingPhase.INVESTIGATION,
                component_id="runForensicsCommand",
                component_type="Lambda",
                event_data=clean_date_format(response),
            )

            cmd_id = response["Command"]["CommandId"]

            ssm_cmd_artifact_map[cmd_id] = {
                "Prefix": "memory-analysis/{0}/{1}".format(
                    instance_id, forensic_id
                ),
                "SSMDocumentName": memory_load_document_name,
                "CommandInputArtifactId": input_artifact_id,
            }

            output_body["InstanceResults"][instance_id][
                "MemoryInvestigation"
            ] = {}
            output_body["InstanceResults"][instance_id]["MemoryInvestigation"][
                "CommandId"
            ] = cmd_id
            output_body["InstanceResults"][instance_id]["MemoryInvestigation"][
                "CommandIdArtifactMap"
            ] = ssm_cmd_artifact_map

            logger.info(output_body)
            return output_body

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        output_body["errorName"] = "Error: Memory Analysis"
        output_body["errorDescription"] = (
            f"Error while performing memory analysis for forensic id:  {forensic_id} forensic investigation instance on forensic Type : {forensic_type}"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "runMemoryAnalysis"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
