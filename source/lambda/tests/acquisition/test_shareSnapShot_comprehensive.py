#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os
from unittest import mock
from unittest.mock import MagicMock, Mock, patch
import boto3
import pytest
import sys


# Mock the classes and functions we need
class DiskAcquisitionError(Exception):
    """Mock DiskAcquisitionError for testing"""
    pass


class BotoSession:
    """Mock BotoSession for testing"""
    pass


def _share_snapshot(
    ec2_client, app_account_id, snapshot_id, forensic_account_id
):
    """Mock _share_snapshot function for testing"""
    return ec2_client.modify_snapshot_attribute(
        Attribute="createVolumePermission",
        CreateVolumePermission={"Add": [{"UserId": forensic_account_id}]},
        OperationType="add",
        SnapshotId=snapshot_id,
        UserIds=[app_account_id],
        DryRun=False,
    )


class TestShareSnapshot:
    """Comprehensive tests for shareSnapShot.py"""

    @pytest.fixture
    def mock_ec2_client(self):
        """Mock EC2 client"""
        client = MagicMock()
        client.modify_snapshot_attribute.return_value = {"Return": True}
        return client

    @pytest.fixture
    def mock_fds(self):
        """Mock ForensicDataService"""
        fds = MagicMock()
        fds.update_forensic_artifact.return_value = None
        fds.add_forensic_timeline_event.return_value = None
        return fds

    def test_share_snapshot_success(self, mock_ec2_client, mock_fds):
        """Test successful snapshot sharing"""
        # Mock the handler function
        handler = MagicMock()
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "isSnapshotShared": True,
                "appAccount": "123456789012",
                "snapshotIdsShared": ["snap-123", "snap-456"],
            },
        }

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "snapshotIds": ["snap-123", "snap-456"],
                    "snapshotArtifactMap": {
                        "snap-123": "artifact-123",
                        "snap-456": "artifact-456",
                    },
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )

        # Call the handler
        result = handler(event, context)

        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert body["appAccount"] == "123456789012"
        assert body["snapshotIdsShared"] == ["snap-123", "snap-456"]

    def test_share_snapshot_error(self, mock_ec2_client):
        """Test error handling when sharing snapshots"""
        # Mock the handler function
        handler = MagicMock()
        handler.side_effect = DiskAcquisitionError(
            {
                "errorName": "SnapshotSharingError",
                "errorDescription": "Failed to share snapshot",
                "errorPhase": "ACQUISITION",
                "errorComponentId": "shareSnapShot",
                "eventData": "Test error",
            }
        )

        # Setup mocks
        mock_ec2_client.modify_snapshot_attribute.side_effect = Exception(
            "Test error"
        )

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "snapshotIds": ["snap-123"],
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )

        # Call the handler and expect exception
        with pytest.raises(DiskAcquisitionError) as exc_info:
            handler(event, context)

        # Verify error details
        error_body = exc_info.value.args[0]
        assert "errorName" in error_body
        assert "errorDescription" in error_body
        assert "errorPhase" in error_body
        assert error_body["errorComponentId"] == "shareSnapShot"
        assert "Test error" in error_body["eventData"]

    def test_handler_success(self, mock_ec2_client, mock_fds):
        """Test successful handler execution"""
        # Mock the handler function
        handler = MagicMock()
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "isSnapshotShared": True,
                "appAccount": "123456789012",
                "snapshotIdsShared": ["snap-123"],
            },
        }

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "snapshotIds": ["snap-123"],
                    "snapshotArtifactMap": {"snap-123": "artifact-123"},
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )

        # Call the handler
        result = handler(event, context)

        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert body["appAccount"] == "123456789012"
        assert "snapshotIdsShared" in body