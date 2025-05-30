#!/usr/bin/python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3
import pytest

from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.loadforensictools import loadForensicTools

event = {}
tokens = {}
ssmResponse = {}


@pytest.fixture(scope="function", autouse=True)
def setupevent(request):

    print("Testing load forensic tools Flow Started ")
    global event
    event = {
        "RequestType": "Create",
        "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-securityHubCustomActioninsta-QM3kDlrE4Nzf",
        "ResponseURL": "https://cloudformation-custom-resource-response-apsoutheast2.s3-ap-southeast-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aap-southeast-2%3A123456789012%3Astack/ForensicSolutionStack",
        "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicSolutionStack/8dfc7990-5942-11ec-93ec-0613a5a5f95a",
        "RequestId": "6715ccf3-ce9a-4eff-b32d-586c71ca8fda",
        "LogicalResourceId": "securityHubCustomActionCustomAction6FF54E59",
        "ResourceType": "Custom::ActionTarget",
        "ResourceProperties": {
            "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-securityHubCustomActioninsta-QM3kDlrE4Nzf",
            "Description": "Trigger Forensic Triage Action",
            "Id": "ForensicTriageAction",
            "Name": "Forensic Triage ",
        },
    }
    global tokens
    tokens = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "FwoGZXIvYXdzEM3//////////SAMPLE",
            "Expiration": "datetime.datetime(2021, 11, 26, 4, 34, 20, tzinfo=tzlocal())",
        }
    }
    global ssmResponse
    ssmResponse = {
        "InstanceInformationList": [
            {
                "InstanceId": "i-0bf2bf6b175654c6e",
                "PingStatus": "Online",
                "LastPingDateTime": "Fri, 26 Nov 2021 20:33:48 GMT",
                "AgentVersion": "3.0.1124.0",
                "IsLatestVersion": False,
                "PlatformType": "Linux",
                "PlatformName": "Ubuntu",
                "PlatformVersion": "20.04",
                "ResourceType": "EC2Instance",
                "IPAddress": "10.1.3.102",
                "ComputerName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
            },
            {
                "InstanceId": "i-0bf2bf6b175654c6e",
                "PingStatus": "Online",
                "LastPingDateTime": "Fri, 26 Nov 2021 20:33:48 GMT",
                "AgentVersion": "3.0.1124.0",
                "IsLatestVersion": False,
                "PlatformType": "Linux",
                "PlatformName": "Amazon Linux",
                "PlatformVersion": "2",
                "ResourceType": "EC2Instance",
                "IPAddress": "10.1.3.238",
                "ComputerName": "ip-10-1-3-238.ap-southeast-2.compute.internal",
            },
        ],
        "ResponseMetadata": {
            "RequestId": "527f7371-131a-4069-bda1-a4e1d5efaa82",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "server": "Server",
                "date": "Fri, 26 Nov 2021 20:33:48 GMT",
                "content-type": "application/x-amz-json-1.1",
                "content-length": "705",
                "connection": "keep-alive",
                "x-amzn-requestid": "527f7371-131a-4069-bda1-a4e1d5efaa82",
            },
            "RetryAttempts": 0,
        },
    }

    # yield
    # print ('Testing Memory Acquisition Flow Completed')
    def teardown():
        print("Testing Forensic Tools Flow Completed")

    request.addfinalizer(teardown)


assume_role_fn = MagicMock(return_value={})
describe_instance_information_fn = MagicMock()
send_command_fn = MagicMock()
modify_document_permission_fn = MagicMock()
describe_subnets_fn = MagicMock()
run_instances_fn = MagicMock()


def setup_positive_mocks():

    describe_instance_information_fn.return_value = ssmResponse
    describe_subnets_fn.return_value = {
        "Subnets": [{"SubnetId": "sub-1234567890"}]
    }
    run_instances_fn.return_value = {
        "Instances": [{"InstanceId": "i-0bf2bf6b175654c6e"}]
    }


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ssm"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.put_item = MagicMock()
    mockClient.assume_role = assume_role_fn
    mockClient.describe_instance_information = describe_instance_information_fn
    mockClient.send_command = send_command_fn
    mockClient.modify_document_permission = modify_document_permission_fn
    mockClient.run_instances = run_instances_fn
    mockClient.describe_subnets = describe_subnets_fn
    return mockClient


def mock_connection_sts():
    mockClient = Mock(boto3.client("sts"))
    mockClient.assume_role = tokens
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "S3_BUCKET_KEY_ARN": "arn:aws:kms:ap-southeast-2:123456789012:key/78dd4742-e6b8-4e1c-acc5-5ad35042a86b",
        "WINDOWS_LIME_MEMORY_ACQUISITION": "documentName",
        "LINUX_LIME_MEMORY_ACQUISITION": "documentName",
        "AMAZON_LINUX_2_VOLATILITY_PROFILE": "documentName",
        "AMAZON_LINUX_2_LIME_VOLATILITY_LOADER": "documentName",
        "SSM_EXECUTION_TIMEOUT": "1800",
        "VPC_ID": "vpc-1234567890",
        "AMI_ID": "ami-1234567890",
        "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
    },
)
def test_happy_path_flow_trigger_event():
    assume_role_fn.return_value = tokens

    describe_instance_information_fn.return_value = ssmResponse
    setup_positive_mocks()
    send_command_fn.return_value = {
        "Command": {
            "CommandId": "73f4f7bb-53a7-4397-8085-c5b6baa8a126",
            "DocumentName": "lime-memory-acquisition",
            "DocumentVersion": "$DEFAULT",
            "Comment": "Memory Acquisition for i-0bf2bf6b175654c6e",
            "ExpiresAfter": "datetime.datetime(2021, 11, 27, 0, 13, 10, 794000, tzinfo=tzlocal())",
            "Parameters": {
                "AccessKeyId": ["AKIAIOSFODNN7EXAMPLE"],
                "Region": ["ap-southeast-2"],
                "SecretAccessKey": [
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                ],
                "SessionToken": ["FwoGZXIvYXdzEM3//////////SAMPLE"],
                "s3bucket": ["forensicsolutionstack-forensicbucket"],
                "s3commands": [
                    "aws s3 cp . s3://forensicsolutionstack-forensicbucket/memory/i-0bf2bf6b175654c6e/c5eddc90-9f06-4517-a684-a68f3744f97e --recursive"
                ],
                "ExecutionTimeout": ["1800"],
            },
            "InstanceIds": ["i-0bf2bf6b175654c6e"],
            "Targets": [],
            "RequestedDateTime": "datetime.datetime(2021, 11, 26, 23, 12, 10, 794000, tzinfo=tzlocal())",
            "Status": "Pending",
            "StatusDetails": "Pending",
            "OutputS3Region": "ap-southeast-2",
            "OutputS3BucketName": "",
            "OutputS3KeyPrefix": "",
            "MaxConcurrency": "50",
            "MaxErrors": "0",
            "TargetCount": 1,
            "CompletedCount": 0,
            "ErrorCount": 0,
            "DeliveryTimedOutCount": 0,
            "ServiceRole": "",
            "NotificationConfig": {
                "NotificationArn": "",
                "NotificationEvents": [],
                "NotificationType": "",
            },
            "CloudWatchOutputConfig": {
                "CloudWatchLogGroupName": "",
                "CloudWatchOutputEnabled": False,
            },
            "TimeoutSeconds": 3600,
        },
        "ResponseMetadata": {
            "RequestId": "9d1696b6-80d6-4df8-aad5-a2367caf4689",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "server": "Server",
                "date": "Fri, 26 Nov 2021 23:12:10 GMT",
                "content-type": "application/x-amz-json-1.1",
                "content-length": "1599",
                "connection": "keep-alive",
                "x-amzn-requestid": "9d1696b6-80d6-4df8-aad5-a2367caf4689",
            },
            "RetryAttempts": 0,
        },
    }

    with patch.object(
        loadForensicTools,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = loadForensicTools.handler(event, context)
        assert ret.get("statusCode") == 200
