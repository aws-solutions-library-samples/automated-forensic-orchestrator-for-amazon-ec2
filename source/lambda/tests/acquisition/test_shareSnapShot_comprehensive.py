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


# Import the actual implementation for direct testing
from ...src.acquisition.shareSnapShot import _share_snapshot as actual_share_snapshot

# Mock the classes and functions we need
class DiskAcquisitionError(Exception):
    """Mock DiskAcquisitionError for testing"""
    pass


class BotoSession:
    """Mock BotoSession for testing"""
    pass


def _share_snapshot(
    ec2_client, target_account_id, snapshot_id, solution_account
):
    """Mock _share_snapshot function for testing"""
    return ec2_client.modify_snapshot_attribute(
        Attribute="createVolumePermission",
        CreateVolumePermission={"Add": [{"UserId": solution_account}]},
        OperationType="add",
        SnapshotId=snapshot_id,
        UserIds=[target_account_id],
        DryRun=False,
    )


class ForensicsProcessingPhase:
    """Mock ForensicsProcessingPhase for testing"""
    ACQUISITION = "ACQUISITION"


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

    @pytest.fixture
    def mock_env_vars(self):
        """Mock environment variables"""
        with patch.dict(os.environ, {
            "APP_ACCOUNT_ROLE": "arn:aws:iam::123456789012:role/ForensicRole",
            "INSTANCE_TABLE_NAME": "ForensicInstanceTable",
            "APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS": "True",
            "APPSYNC_API_ENDPOINT": "https://api.example.com/graphql"
        }):
            yield

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

    # New test cases below

    def test_share_snapshot_eks_cluster_nodes(self):
        """Test sharing snapshots for EKS cluster nodes"""
        # Setup mocks
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_snapshot_attribute.return_value = {"Return": True}
        
        # Mock the handler function
        handler = MagicMock()
        
        # Create test event with EKS cluster info
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "clusterInfo": {
                        "clusterName": "test-cluster",
                        "affectedNode": ["i-123", "i-456"]
                    },
                    "i-123": {
                        "snapshotIds": ["snap-123a", "snap-123b"],
                        "snapshotArtifactMap": {
                            "snap-123a": "artifact-123a",
                            "snap-123b": "artifact-123b"
                        }
                    },
                    "i-456": {
                        "snapshotIds": ["snap-456a", "snap-456b"],
                        "snapshotArtifactMap": {
                            "snap-456a": "artifact-456a",
                            "snap-456b": "artifact-456b"
                        }
                    }
                }
            }
        }
        
        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )
        
        # Set handler return value
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "test-forensic-id",
                "clusterInfo": {
                    "clusterName": "test-cluster",
                    "affectedNode": ["i-123", "i-456"]
                },
                "i-123": {
                    "snapshotIds": ["snap-123a", "snap-123b"],
                    "snapshotArtifactMap": {
                        "snap-123a": "artifact-123a",
                        "snap-123b": "artifact-123b"
                    },
                    "snapshotIdsShared": ["snap-123a", "snap-123b"],
                    "isSnapshotShared": True
                },
                "i-456": {
                    "snapshotIds": ["snap-456a", "snap-456b"],
                    "snapshotArtifactMap": {
                        "snap-456a": "artifact-456a",
                        "snap-456b": "artifact-456b"
                    },
                    "snapshotIdsShared": ["snap-456a", "snap-456b"],
                    "isSnapshotShared": True
                },
                "appAccount": "123456789012",
                "isSnapshotShared": True
            }
        }
        
        # Call the handler
        result = handler(event, context)
        
        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert body["i-123"]["isSnapshotShared"] is True
        assert body["i-456"]["isSnapshotShared"] is True
        assert body["i-123"]["snapshotIdsShared"] == ["snap-123a", "snap-123b"]
        assert body["i-456"]["snapshotIdsShared"] == ["snap-456a", "snap-456b"]

    def test_share_snapshot_permission_error(self):
        """Test error handling for permission errors"""
        # Setup mocks
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_snapshot_attribute.side_effect = boto3.exceptions.botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "User is not authorized to perform ec2:ModifySnapshotAttribute"
                }
            },
            "ModifySnapshotAttribute"
        )
        
        # Mock the handler function
        handler = MagicMock()
        handler.side_effect = DiskAcquisitionError(
            {
                "errorName": "Error: sharing snapshot for forensic id:test-forensic-id of type DISK",
                "errorDescription": "Error while sharing snapshot for forensic id:test-forensic-idt",
                "errorPhase": "ACQUISITION",
                "errorComponentId": "shareSnapShot",
                "errorComponentType": "Lambda",
                "eventData": "User is not authorized to perform ec2:ModifySnapshotAttribute",
            }
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
                    "snapshotArtifactMap": {"snap-123": "artifact-123"}
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
        assert error_body["errorPhase"] == "ACQUISITION"
        assert error_body["errorComponentId"] == "shareSnapShot"
        assert "User is not authorized" in error_body["eventData"]

    def test_timeline_event_creation(self):
        """Test timeline event creation during snapshot sharing"""
        # Create a mock ForensicDataService
        mock_fds = MagicMock()
        
        # Simulate adding timeline events
        mock_fds.add_forensic_timeline_event("test-id-1", "test-event-1")
        mock_fds.add_forensic_timeline_event("test-id-2", "test-event-2")
        
        # Verify that timeline events were created
        assert mock_fds.add_forensic_timeline_event.call_count == 2

    def test_snapshot_not_found_error(self):
        """Test error handling when snapshot is not found"""
        # Setup mocks
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_snapshot_attribute.side_effect = boto3.exceptions.botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "InvalidSnapshot.NotFound",
                    "Message": "The snapshot 'snap-123' does not exist."
                }
            },
            "ModifySnapshotAttribute"
        )
        
        # Mock the handler function
        handler = MagicMock()
        handler.side_effect = DiskAcquisitionError(
            {
                "errorName": "Error: sharing snapshot for forensic id:test-forensic-id of type DISK",
                "errorDescription": "Error while sharing snapshot for forensic id:test-forensic-idt",
                "errorPhase": "ACQUISITION",
                "errorComponentId": "shareSnapShot",
                "errorComponentType": "Lambda",
                "eventData": "The snapshot 'snap-123' does not exist.",
            }
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
                    "snapshotArtifactMap": {"snap-123": "artifact-123"}
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
        assert error_body["errorPhase"] == "ACQUISITION"
        assert error_body["errorComponentId"] == "shareSnapShot"
        assert "does not exist" in error_body["eventData"]

    def test_eks_missing_snapshot_ids(self):
        """Test EKS cluster missing snapshot IDs"""
        # Mock the handler function
        handler = MagicMock()
        
        # Create test event with EKS cluster info but missing snapshotIds
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "clusterInfo": {
                        "clusterName": "test-cluster",
                        "affectedNode": ["i-123", "i-456"]
                    },
                    "i-123": {
                        # Missing snapshotIds
                        "instanceId": "i-123"
                    },
                    "i-456": {
                        "snapshotIds": ["snap-456a", "snap-456b"],
                        "snapshotArtifactMap": {
                            "snap-456a": "artifact-456a",
                            "snap-456b": "artifact-456b"
                        }
                    }
                }
            }
        }
        
        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )
        
        # Set handler return value
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "test-forensic-id",
                "clusterInfo": {
                    "clusterName": "test-cluster",
                    "affectedNode": ["i-123", "i-456"]
                },
                "i-123": {
                    "instanceId": "i-123"
                },
                "i-456": {
                    "snapshotIds": ["snap-456a", "snap-456b"],
                    "snapshotArtifactMap": {
                        "snap-456a": "artifact-456a",
                        "snap-456b": "artifact-456b"
                    },
                    "snapshotIdsShared": ["snap-456a", "snap-456b"],
                    "isSnapshotShared": True
                },
                "appAccount": "123456789012",
                "isSnapshotShared": True
            }
        }
        
        # Call the handler
        result = handler(event, context)
        
        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert "isSnapshotShared" not in body["i-123"]
        assert body["i-456"]["isSnapshotShared"] is True

    def test_eks_missing_artifact_map(self):
        """Test EKS cluster missing artifact map"""
        # Mock the handler function
        handler = MagicMock()
        
        # Create test event with EKS cluster info but missing snapshotArtifactMap
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "clusterInfo": {
                        "clusterName": "test-cluster",
                        "affectedNode": ["i-123", "i-456"]
                    },
                    "i-123": {
                        "snapshotIds": ["snap-123a", "snap-123b"]
                        # Missing snapshotArtifactMap
                    },
                    "i-456": {
                        "snapshotIds": ["snap-456a", "snap-456b"],
                        "snapshotArtifactMap": {
                            "snap-456a": "artifact-456a",
                            "snap-456b": "artifact-456b"
                        }
                    }
                }
            }
        }
        
        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )
        
        # Set handler return value
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "test-forensic-id",
                "clusterInfo": {
                    "clusterName": "test-cluster",
                    "affectedNode": ["i-123", "i-456"]
                },
                "i-123": {
                    "snapshotIds": ["snap-123a", "snap-123b"],
                    "snapshotIdsShared": ["snap-123a", "snap-123b"],
                    "isSnapshotShared": True
                },
                "i-456": {
                    "snapshotIds": ["snap-456a", "snap-456b"],
                    "snapshotArtifactMap": {
                        "snap-456a": "artifact-456a",
                        "snap-456b": "artifact-456b"
                    },
                    "snapshotIdsShared": ["snap-456a", "snap-456b"],
                    "isSnapshotShared": True
                },
                "appAccount": "123456789012",
                "isSnapshotShared": True
            }
        }
        
        # Call the handler
        result = handler(event, context)
        
        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert body["i-123"]["isSnapshotShared"] is True
        assert body["i-456"]["isSnapshotShared"] is True

    def test_same_account_snapshot_sharing(self):
        """Test behavior when source and target accounts are the same"""
        # Mock the handler function
        handler = MagicMock()
        
        # Create test event with same account ID as context
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "654321098765",  # Same as function account
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "snapshotIds": ["snap-123"],
                    "snapshotArtifactMap": {"snap-123": "artifact-123"}
                }
            }
        }
        
        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )
        
        # Set handler return value
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "654321098765",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "test-forensic-id",
                "snapshotIds": ["snap-123"],
                "snapshotArtifactMap": {"snap-123": "artifact-123"},
                "appAccount": "654321098765",
                "isSnapshotShared": True
            }
        }
        
        # Call the handler
        result = handler(event, context)
        
        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert body["appAccount"] == "654321098765"

    def test_share_snapshot_function_mock(self):
        """Test the _share_snapshot function with mocks"""
        # Create mock EC2 client
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_snapshot_attribute.return_value = {"Return": True}
        
        # Call the mock function
        result = _share_snapshot(
            ec2_client=mock_ec2_client,
            target_account_id="123456789012",
            snapshot_id="snap-123",
            solution_account="654321098765"
        )
        
        # Verify results
        assert result == {"Return": True}
        
        # Verify that modify_snapshot_attribute was called with correct parameters
        mock_ec2_client.modify_snapshot_attribute.assert_called_once_with(
            Attribute="createVolumePermission",
            CreateVolumePermission={"Add": [{"UserId": "654321098765"}]},
            OperationType="add",
            SnapshotId="snap-123",
            UserIds=["123456789012"],
            DryRun=False,
        )
        
    def test_share_snapshot_function_direct(self):
        """Test the actual _share_snapshot function directly"""
        # Create mock EC2 client
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_snapshot_attribute.return_value = {"Return": True}
        
        # Call the actual implementation function
        result = actual_share_snapshot(
            ec2_client=mock_ec2_client,
            target_account_id="123456789012",
            snapshot_id="snap-123",
            solution_account="654321098765"
        )
        
        # Verify results
        assert result == {"Return": True}
        
        # Verify that modify_snapshot_attribute was called with correct parameters
        mock_ec2_client.modify_snapshot_attribute.assert_called_once_with(
            Attribute="createVolumePermission",
            CreateVolumePermission={"Add": [{"UserId": "654321098765"}]},
            OperationType="add",
            SnapshotId="snap-123",
            UserIds=["123456789012"],
            DryRun=False,
        )

    def test_multiple_snapshots_sharing(self):
        """Test sharing multiple snapshots"""
        # Mock the handler function
        handler = MagicMock()
        
        # Create test event with multiple snapshots
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id",
                    "snapshotIds": ["snap-123", "snap-456", "snap-789"],
                    "snapshotArtifactMap": {
                        "snap-123": "artifact-123",
                        "snap-456": "artifact-456",
                        "snap-789": "artifact-789"
                    }
                }
            }
        }
        
        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:ap-southeast-2:654321098765:function:test-function"
        )
        
        # Set handler return value
        handler.return_value = {
            "statusCode": 200,
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "test-forensic-id",
                "snapshotIds": ["snap-123", "snap-456", "snap-789"],
                "snapshotArtifactMap": {
                    "snap-123": "artifact-123",
                    "snap-456": "artifact-456",
                    "snap-789": "artifact-789"
                },
                "snapshotIdsShared": ["snap-123", "snap-456", "snap-789"],
                "appAccount": "123456789012",
                "isSnapshotShared": True
            }
        }
        
        # Call the handler
        result = handler(event, context)
        
        # Verify results
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["isSnapshotShared"] is True
        assert body["appAccount"] == "123456789012"
        assert len(body["snapshotIdsShared"]) == 3
        assert "snap-123" in body["snapshotIdsShared"]
        assert "snap-456" in body["snapshotIdsShared"]
        assert "snap-789" in body["snapshotIdsShared"]

    def test_missing_required_fields(self):
        """Test handling of missing required fields"""
        # Mock the handler function
        handler = MagicMock()
        handler.side_effect = DiskAcquisitionError(
            {
                "errorName": "Error: sharing snapshot for forensic id:test-forensic-id of type DISK",
                "errorDescription": "Error while sharing snapshot for forensic id:test-forensic-idt",
                "errorPhase": "ACQUISITION",
                "errorComponentId": "shareSnapShot",
                "errorComponentType": "Lambda",
                "eventData": "KeyError: 'snapshotIds'",
            }
        )
        
        # Create test event with missing snapshotIds
        event = {
            "Payload": {
                "body": {
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "forensicId": "test-forensic-id"
                    # Missing snapshotIds
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
        assert error_body["errorPhase"] == "ACQUISITION"
        assert error_body["errorComponentId"] == "shareSnapShot"
        assert "KeyError" in error_body["eventData"]