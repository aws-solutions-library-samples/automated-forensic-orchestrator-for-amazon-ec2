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
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import pytest

from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.common.exception import InvestigationError
from ...src.kernelInstance.terminator import handler as function_under_test


@pytest.fixture(scope="function", autouse=True)
def setup_event(request):
    print("Testing Terminate Builder Instance Started")
    global event
    event = {
        "Payload": {
            "body": {
                "InstanceId": "i-1234567890abcdef0",
                "forensicId": "test-forensic-id",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
            }
        }
    }

    def teardown():
        print("Testing Terminate Builder Instance Completed")

    request.addfinalizer(teardown)


def mock_connection():
    mockClient = Mock()
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.terminate_instances = MagicMock(return_value={})
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_success():
    """Test successful instance termination"""
    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        result = function_under_test(event, "")

        assert result.get("statusCode") == 200
        assert result.get("body").get("InstanceId") == "i-1234567890abcdef0"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_failure():
    """Test instance termination failure"""
    mock_client = mock_connection()
    mock_client.terminate_instances.side_effect = Exception("EC2 API Error")

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_client),
    ), pytest.raises(InvestigationError) as exc_info:
        function_under_test(event, "")

    # InvestigationError contains the error body as a JSON string
    import json

    error_body = json.loads(str(exc_info.value))
    assert error_body["errorName"] == "Error: Terminating Builder Instance"
    assert (
        error_body["errorDescription"]
        == "Error while terminating builder instance i-1234567890abcdef0 instance"
    )
    assert error_body["errorPhase"] == "INVESTIGATION"
    assert error_body["errorComponentId"] == "terminateBuilderInstance"
    assert error_body["errorComponentType"] == "Lambda"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_with_different_instance_id():
    """Test termination with different instance ID"""
    test_event = {
        "Payload": {
            "body": {
                "InstanceId": "i-0987654321fedcba0",
                "forensicId": "test-forensic-id-2",
            }
        }
    }

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        result = function_under_test(test_event, "")

        assert result.get("statusCode") == 200
        assert result.get("body").get("InstanceId") == "i-0987654321fedcba0"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-west-2",
    },
)
def test_terminate_instance_different_region():
    """Test termination in different region"""
    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        result = function_under_test(event, "")

        assert result.get("statusCode") == 200
        # Just verify the function completes successfully with different region
        assert result.get("body").get("InstanceId") == "i-1234567890abcdef0"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_preserves_input_body():
    """Test that input body is preserved in output"""
    test_event = {
        "Payload": {
            "body": {
                "InstanceId": "i-1234567890abcdef0",
                "forensicId": "test-forensic-id",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
                "additionalData": "test-data",
            }
        }
    }

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        result = function_under_test(test_event, "")

        assert result.get("statusCode") == 200
        body = result.get("body")
        assert body.get("InstanceId") == "i-1234567890abcdef0"
        assert body.get("forensicId") == "test-forensic-id"
        assert body.get("instanceAccount") == "123456789012"
        assert body.get("instanceRegion") == "us-east-1"
        assert body.get("additionalData") == "test-data"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_ec2_client_creation():
    """Test that EC2 client is created correctly"""
    mock_client = mock_connection()

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_client),
    ) as mock_get_connection:
        function_under_test(event, "")

        # Verify get_connection was called with "ec2" (may be called multiple times due to internal AWS client usage)
        calls = mock_get_connection.call_args_list
        ec2_calls = [call for call in calls if call[0][0] == "ec2"]
        assert (
            len(ec2_calls) >= 1
        ), f"Expected at least one call with 'ec2', got calls: {calls}"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_boto_client_error():
    """Test handling of boto client errors"""
    from botocore.exceptions import ClientError

    mock_client = mock_connection()
    mock_client.terminate_instances.side_effect = ClientError(
        {
            "Error": {
                "Code": "InvalidInstanceID.NotFound",
                "Message": "Instance not found",
            }
        },
        "TerminateInstances",
    )

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_client),
    ), pytest.raises(InvestigationError) as exc_info:
        function_under_test(event, "")

    # InvestigationError contains the error body as a JSON string
    import json

    error_body = json.loads(str(exc_info.value))
    assert error_body["errorName"] == "Error: Terminating Builder Instance"
    assert "InvalidInstanceID.NotFound" in error_body["eventData"]


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "us-east-1",
    },
)
def test_terminate_instance_calls_terminate_instances():
    """Test that terminate_instances is called with correct parameters"""
    mock_client = mock_connection()

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_client),
    ):
        function_under_test(event, "")

        # Verify terminate_instances was called with correct parameters
        mock_client.terminate_instances.assert_called_with(
            InstanceIds=["i-1234567890abcdef0"]
        )
