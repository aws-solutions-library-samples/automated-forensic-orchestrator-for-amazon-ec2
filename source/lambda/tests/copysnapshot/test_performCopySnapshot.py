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
from unittest.mock import MagicMock, patch
import pytest

from ...src.copysnapshot import performCopySnapshot
from ...src.common.exception import InvestigationError
from ...src.data.exceptions import DoesNotExistException


@pytest.fixture
def mock_forensic_record():
    """Mock forensic record for testing"""
    record = MagicMock()
    record.resourceId = "i-1234567890abcdef0"
    return record


@pytest.fixture
def copy_snapshot_event_ec2():
    """Test event for EC2 snapshot copy"""
    return {
        "Payload": {
            "body": {
                "forensicId": "test-forensic-id",
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
                "snapshotIds": ["snap-123", "snap-456"],
                "isSnapshotShared": False,
            }
        }
    }


@pytest.fixture
def copy_snapshot_event_shared():
    """Test event for shared snapshot copy"""
    return {
        "Payload": {
            "body": {
                "forensicId": "test-forensic-id",
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
                "snapshotIds": ["snap-123", "snap-456"],
                "isSnapshotShared": True,
            }
        }
    }


@pytest.fixture
def copy_snapshot_event_eks():
    """Test event for EKS snapshot copy"""
    return {
        "Payload": {
            "body": {
                "forensicId": "test-forensic-id",
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
                "isSnapshotShared": False,
                "clusterInfo": {"affectedNode": ["i-123", "i-456"]},
                "i-123": {"snapshotIds": ["snap-123"]},
                "i-456": {"snapshotIds": ["snap-456"]},
            }
        }
    }


@pytest.fixture
def context():
    """Mock Lambda context"""
    context = MagicMock()
    context.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:123456789012:function:test-function"
    )
    return context


class TestCopySnapshotFunctions:
    """Test copy snapshot functionality from copysnapshot/performCopySnapshot.py"""

    @patch.dict(
        os.environ,
        {
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
            "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias",
        },
    )
    @patch("lambda.src.copysnapshot.performCopySnapshot.ForensicDataService")
    @patch("lambda.src.copysnapshot.performCopySnapshot.create_aws_client")
    def test_copy_snapshot_ec2_not_shared_success(
        self,
        mock_create_aws_client,
        mock_fds_class,
        copy_snapshot_event_ec2,
        context,
        mock_forensic_record,
    ):
        """Test successful EC2 snapshot copy when not shared"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record

        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123"},
            {"SnapshotId": "snap-copy-456"},
        ]
        mock_create_aws_client.return_value = mock_ec2_client

        # Call the actual handler function
        result = performCopySnapshot.handler(copy_snapshot_event_ec2, context)

        # Verify response
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["instanceId"] == "i-1234567890abcdef0"
        assert "copySnapshotIds" in body
        assert "isCopySnapShotComplete" in body
        assert body["isCopySnapShotComplete"] is False
        
        # Verify the EC2 client was called correctly
        mock_create_aws_client.assert_called()
        mock_ec2_client.copy_snapshot.assert_called()
        assert mock_ec2_client.copy_snapshot.call_count == 2

    @patch.dict(
        os.environ,
        {
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
            "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias",
        },
    )
    @patch("lambda.src.copysnapshot.performCopySnapshot.ForensicDataService")
    @patch("lambda.src.copysnapshot.performCopySnapshot.create_aws_client")
    def test_copy_snapshot_forensic_record_error(
        self,
        mock_create_aws_client,
        mock_fds_class,
        copy_snapshot_event_ec2,
        context,
    ):
        """Test copy snapshot when forensic record retrieval fails with a custom error"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.side_effect = DoesNotExistException(
            "Resource with id test-forensic-id does not exist"
        )

        # The handler should raise an InvestigationError when the record doesn't exist
        with pytest.raises(InvestigationError) as exc_info:
            performCopySnapshot.handler(copy_snapshot_event_ec2, context)

        # Verify the error message contains the forensic ID
        assert "test-forensic-id" in str(exc_info.value)

    @patch.dict(
        os.environ,
        {
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
            "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias",
        },
    )
    @patch("lambda.src.copysnapshot.performCopySnapshot.ForensicDataService")
    @patch("lambda.src.copysnapshot.performCopySnapshot.create_aws_client")
    def test_copy_snapshot_ec2_shared_success(
        self,
        mock_create_aws_client,
        mock_fds_class,
        copy_snapshot_event_shared,
        context,
        mock_forensic_record,
    ):
        """Test successful EC2 snapshot copy when shared"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record

        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123"},
            {"SnapshotId": "snap-copy-456"},
        ]
        mock_create_aws_client.return_value = mock_ec2_client

        # Call the actual handler function
        result = performCopySnapshot.handler(copy_snapshot_event_shared, context)

        # Verify response for shared snapshot
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["instanceId"] == "i-1234567890abcdef0"
        assert "app_snapshotIds" in body
        assert "forensicCopysnapshotIds" in body
        assert body["isAppCopySnapShotComplete"] is False
        
        # Verify the EC2 client was called correctly
        mock_create_aws_client.assert_called()
        mock_ec2_client.copy_snapshot.assert_called()
        assert mock_ec2_client.copy_snapshot.call_count == 2

    @patch.dict(
        os.environ,
        {
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
            "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias",
        },
    )
    @patch("lambda.src.copysnapshot.performCopySnapshot.ForensicDataService")
    @patch("lambda.src.copysnapshot.performCopySnapshot.create_aws_client")
    def test_copy_snapshot_eks_success(
        self,
        mock_create_aws_client,
        mock_fds_class,
        copy_snapshot_event_eks,
        context,
        mock_forensic_record,
    ):
        """Test successful EKS snapshot copy"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record

        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123"},
            {"SnapshotId": "snap-copy-456"},
        ]
        mock_create_aws_client.return_value = mock_ec2_client

        # Call the actual handler function
        result = performCopySnapshot.handler(copy_snapshot_event_eks, context)

        # Verify response
        assert result["statusCode"] == 200
        body = result["body"]
        assert "instanceId" in body
        assert isinstance(body["instanceId"], list)
        assert "i-123" in body
        assert "i-456" in body
        assert "copySnapshotIds" in body["i-123"]
        assert "copySnapshotIds" in body["i-456"]
        assert body["i-123"]["isCopyComplete"] is False
        assert body["i-456"]["isCopyComplete"] is False
        
        # Verify the EC2 client was called correctly
        mock_create_aws_client.assert_called()
        mock_ec2_client.copy_snapshot.assert_called()
        assert mock_ec2_client.copy_snapshot.call_count == 2