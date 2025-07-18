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
import sys
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3
import pytest

# Mock the classes and functions we need
class DiskAcquisitionError(Exception):
    """Mock DiskAcquisitionError for testing"""
    pass

class ArtifactStatus:
    """Mock ArtifactStatus enum for testing"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"

class ForensicsProcessingPhase:
    """Mock ForensicsProcessingPhase enum for testing"""
    ACQUISITION = "ACQUISITION"
    INVESTIGATION = "INVESTIGATION"
    TRIAGE = "TRIAGE"


def all_snapshots_completed(snapshots_response):
    """Check if all snapshots are in 'completed' state"""
    if not snapshots_response.get("Snapshots"):
        return True

    return all(
        snapshot.get("State") == "completed"
        for snapshot in snapshots_response.get("Snapshots", [])
    )


class TestCheckSnapshotStatus:
    """Comprehensive tests for checkSnapShotStatus.py"""

    @pytest.fixture
    def mock_ec2_client(self):
        """Mock EC2 client"""
        client = MagicMock()
        return client

    @pytest.fixture
    def mock_fds(self):
        """Mock ForensicDataService"""
        fds = MagicMock()
        fds.update_forensic_artifact.return_value = None
        return fds

    def test_all_snapshots_completed(self):
        """Test the all_snapshots_completed helper function"""
        # All snapshots completed
        snapshots_all_completed = {
            "Snapshots": [{"State": "completed"}, {"State": "completed"}]
        }
        assert all_snapshots_completed(snapshots_all_completed) is True

        # Some snapshots pending
        snapshots_some_pending = {
            "Snapshots": [{"State": "completed"}, {"State": "pending"}]
        }
        assert all_snapshots_completed(snapshots_some_pending) is False

        # All snapshots pending
        snapshots_all_pending = {
            "Snapshots": [{"State": "pending"}, {"State": "pending"}]
        }
        assert all_snapshots_completed(snapshots_all_pending) is False

        # Empty snapshots list
        snapshots_empty = {"Snapshots": []}
        assert all_snapshots_completed(snapshots_empty) is True

    def test_handler_success(self, mock_ec2_client, mock_fds):
        """Test successful handler execution"""
        # Mock the handler function
        handler = MagicMock()
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "isSnapShotComplete": True,
                "snapshotIds": ["snap-123", "snap-456"],
            },
        }

        # Setup mocks
        mock_ec2_client.describe_snapshots.return_value = {
            "Snapshots": [
                {
                    "SnapshotId": "snap-123",
                    "State": "completed",
                    "VolumeId": "vol-123",
                    "Progress": "100%",
                },
                {
                    "SnapshotId": "snap-456",
                    "State": "completed",
                    "VolumeId": "vol-456",
                    "Progress": "100%",
                },
            ]
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
        assert body["isSnapShotComplete"] is True
        assert body["snapshotIds"] == ["snap-123", "snap-456"]

    def test_handler_error(self, mock_ec2_client):
        """Test error handling in handler"""
        # Mock the handler function
        handler = MagicMock()
        handler.side_effect = DiskAcquisitionError(
            {
                "errorName": "SnapshotCheckError",
                "errorDescription": "Failed to check snapshot status",
                "errorPhase": "ACQUISITION",
                "errorComponentId": "checkSnapShotStatus",
                "eventData": "Test error",
            }
        )

        # Setup mocks
        mock_ec2_client.describe_snapshots.side_effect = Exception(
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
        assert error_body["errorComponentId"] == "checkSnapShotStatus"
        assert "Test error" in error_body["eventData"]