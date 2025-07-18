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

from unittest.mock import MagicMock, Mock, patch

import pytest

from ...src.kernelchecker.checkBuildingState import (
    handler as function_under_test,
)


@pytest.fixture(scope="function", autouse=True)
def setup_event(request):
    print("Testing Check Building State Started")
    global event
    event = {
        "Payload": {
            "body": {
                "InstanceId": "i-1234567890abcdef0",
                "CommandId": "12345678-1234-1234-1234-123456789012",
                "forensicId": "test-forensic-id",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
            }
        }
    }

    def teardown():
        print("Testing Check Building State Completed")

    request.addfinalizer(teardown)


# Mock waiter that succeeds
class MockWaiterSuccess:
    def wait(self, CommandId, InstanceId, WaiterConfig):
        pass  # Successful wait


# Mock waiter that fails
class MockWaiterFailure:
    def wait(self, CommandId, InstanceId, WaiterConfig):
        raise Exception("Command execution failed")


def mock_ssm_client_success():
    mockClient = Mock()
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.get_waiter = MagicMock(return_value=MockWaiterSuccess())
    return mockClient


def mock_ssm_client_failure():
    mockClient = Mock()
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.get_waiter = MagicMock(return_value=MockWaiterFailure())
    return mockClient


def test_check_building_state_success():
    """Test successful building state check"""
    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client",
        Mock(return_value=mock_ssm_client_success()),
    ):
        result = function_under_test(event, "")

        assert result.get("statusCode") == 200
        body = result.get("body")
        assert body.get("isInstanceProfileBuildingComplete") is True
        assert body.get("InstanceId") == "i-1234567890abcdef0"
        assert body.get("CommandId") == "12345678-1234-1234-1234-123456789012"


def test_check_building_state_failure():
    """Test building state check failure"""
    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client",
        Mock(return_value=mock_ssm_client_failure()),
    ):
        result = function_under_test(event, "")

        assert result.get("statusCode") == 200
        body = result.get("body")
        assert body.get("isInstanceProfileBuildingComplete") is False
        assert body.get("InstanceId") == "i-1234567890abcdef0"


def test_check_building_state_waiter_configuration():
    """Test that waiter is configured correctly"""
    mock_waiter = Mock()
    mock_client = mock_ssm_client_success()
    mock_client.get_waiter.return_value = mock_waiter

    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client",
        Mock(return_value=mock_client),
    ):
        function_under_test(event, "")

        # Verify waiter was called with correct parameters
        mock_client.get_waiter.assert_called_once_with("command_executed")
        mock_waiter.wait.assert_called_once_with(
            CommandId="12345678-1234-1234-1234-123456789012",
            InstanceId="i-1234567890abcdef0",
            WaiterConfig={"Delay": 60, "MaxAttempts": 3},
        )


def test_check_building_state_different_command_id():
    """Test with different command ID"""
    test_event = {
        "Payload": {
            "body": {
                "InstanceId": "i-0987654321fedcba0",
                "CommandId": "87654321-4321-4321-4321-210987654321",
                "forensicId": "test-forensic-id-2",
            }
        }
    }

    mock_waiter = Mock()
    mock_client = mock_ssm_client_success()
    mock_client.get_waiter.return_value = mock_waiter

    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client",
        Mock(return_value=mock_client),
    ):
        result = function_under_test(test_event, "")

        assert result.get("statusCode") == 200
        body = result.get("body")
        assert body.get("isInstanceProfileBuildingComplete") is True
        assert body.get("InstanceId") == "i-0987654321fedcba0"
        assert body.get("CommandId") == "87654321-4321-4321-4321-210987654321"

        mock_waiter.wait.assert_called_once_with(
            CommandId="87654321-4321-4321-4321-210987654321",
            InstanceId="i-0987654321fedcba0",
            WaiterConfig={"Delay": 60, "MaxAttempts": 3},
        )


def test_check_building_state_preserves_input_data():
    """Test that all input data is preserved in output"""
    test_event = {
        "Payload": {
            "body": {
                "InstanceId": "i-1234567890abcdef0",
                "CommandId": "12345678-1234-1234-1234-123456789012",
                "forensicId": "test-forensic-id",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
                "additionalData": "test-data",
                "buildingPhase": "kernel-symbols",
            }
        }
    }

    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client",
        Mock(return_value=mock_ssm_client_success()),
    ):
        result = function_under_test(test_event, "")

        assert result.get("statusCode") == 200
        body = result.get("body")
        assert body.get("isInstanceProfileBuildingComplete") is True
        assert body.get("InstanceId") == "i-1234567890abcdef0"
        assert body.get("CommandId") == "12345678-1234-1234-1234-123456789012"
        assert body.get("forensicId") == "test-forensic-id"
        assert body.get("instanceAccount") == "123456789012"
        assert body.get("instanceRegion") == "us-east-1"
        assert body.get("additionalData") == "test-data"
        assert body.get("buildingPhase") == "kernel-symbols"


def test_check_building_state_timeout_exception():
    """Test handling of timeout exception"""

    class TimeoutException(Exception):
        pass

    def mock_ssm_client_timeout():
        mockClient = Mock()
        mockClient.get_caller_identity = lambda: {}
        mockClient._get_local_account_id = lambda: {}
        mock_waiter = Mock()
        mock_waiter.wait.side_effect = TimeoutException("Waiter timeout")
        mockClient.get_waiter = MagicMock(return_value=mock_waiter)
        return mockClient

    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client",
        Mock(return_value=mock_ssm_client_timeout()),
    ):
        result = function_under_test(event, "")

        assert result.get("statusCode") == 200
        body = result.get("body")
        assert body.get("isInstanceProfileBuildingComplete") is False
        assert body.get("InstanceId") == "i-1234567890abcdef0"


def test_check_building_state_ssm_client_creation():
    """Test that SSM client is created correctly"""
    with patch(
        "lambda.src.kernelchecker.checkBuildingState.create_aws_client"
    ) as mock_create_client:
        mock_create_client.return_value = mock_ssm_client_success()

        function_under_test(event, "")

        mock_create_client.assert_called_once_with("ssm")
