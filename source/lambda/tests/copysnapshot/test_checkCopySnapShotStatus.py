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

import boto3
import pytest

from ...src.common.awsapi_cached_client import AWSCachedClient, BotoSession
from ...src.copysnapshot import checkCopySnapShotStatus
from ...src.data.datatypes import ForensicsProcessingPhase


@pytest.fixture()
def eb_event():
    return {
        "Payload": {
            "body": {
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "forensicType": "DISK",
                "snapshotIds": ["snap-097e3ce579357377b"],
                "copySnapshotIds": ["snap-097e3ce579357377c"],
            },
            "statusCode": 200,
        }
    }


def forensic_record():
    return {
        "resourceId": {"S": "i-01abc123def"},
        "resourceInfo": {
            "M": {
                "BlockDeviceMappings": {
                    "L": [
                        {
                            "M": {
                                "DeviceName": {"S": "/dev/xvda"},
                                "Ebs": {
                                    "M": {
                                        "Status": {"S": "attached"},
                                        "VolumeId": {
                                            "S": "vol-0fa9fbf1a0323a04f"
                                        },
                                        "AttachTime": {
                                            "S": "2021-11-18T04:58:54+00:00"
                                        },
                                        "DeleteOnTermination": {"BOOL": True},
                                    }
                                },
                            }
                        }
                    ]
                },
                "IamInstanceProfile": {
                    "M": {
                        "Arn": {
                            "S": "arn:aws:iam::123456789012:instance-profile/SSMDefaultRole"
                        },
                        "Id": {"S": "AIPAYFFB3ORIFIFKOTFH4"},
                    }
                },
                "SubnetId": {"S": "subnet-0be828943dae437d0"},
                "EbsOptimized": {"BOOL": False},
                "Placement": {
                    "M": {
                        "GroupName": {"S": ""},
                        "Tenancy": {"S": "default"},
                        "AvailabilityZone": {"S": "ap-southeast-2b"},
                    }
                },
                "EnclaveOptions": {"M": {"Enabled": {"BOOL": False}}},
            }
        }
    }


def get_update_record_event():
    return {"Attributes": forensic_record()}


def get_item_event():
    return {"Item": forensic_record()}


get_item_fn = MagicMock(return_value=get_item_event())
describe_snapshot_fn = MagicMock()
put_item_fn = MagicMock(return_value={})
update_item_fn = MagicMock()
assume_role_fn = MagicMock(return_value={})
transact_write_item_fn = MagicMock(return_value={})


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.describe_snapshots = describe_snapshot_fn
    mockClient.get_item = get_item_fn
    mockClient.put_item = put_item_fn
    mockClient.update_item = update_item_fn
    mockClient.assume_role = assume_role_fn
    mockClient.transact_write_items = transact_write_item_fn

    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_snapshot_completed():
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "snapshotIds": ["snap-097e3ce579357377b"],
                "copySnapshotIds": ["snap-097e3ce579357377c"],
                "snapshotArtifactMap": {
                    "snap-097e3ce579357377b": "d0b18a74-c2f1-4309-b17d-c8253b01ab29"
                },
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
            },
            "statusCode": 200,
        }
    }
    describe_snapshot_fn.return_value = {
        "NextToken": "",
        "Snapshots": [
            {
                "Description": "This is my snapshot.",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-097e3ce579357377b",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "completed",
                "VolumeId": "vol-049df61146c4d7901",
                "VolumeSize": 8,
            },
        ],
    }

    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkCopySnapShotStatus.handler(event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isSnapShotCopyComplete") == True


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_snapshot_inprogress():
    event = {
        "Payload": {
            "body": {
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "forensicType": "DISK",
                "snapshotIds": ["snap-097e3ce579357377b"],
                "copySnapshotIds": ["snap-097e3ce579357377c"],
                "snapshotArtifactMap": {
                    "snap-097e3ce579357377b": "d0b18a74-c2f1-4309-b17d-c8253b01ab29"
                },
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
            },
            "statusCode": 200,
        }
    }
    describe_snapshot_fn.return_value = {
        "NextToken": "",
        "Snapshots": [
            {
                "Description": "This is my snapshot.",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-1234567890abcdef0",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "pending",
                "VolumeId": "vol-049df61146c4d7901",
                "VolumeSize": 8,
            },
            {
                "Description": "This is my snapshot.",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-1234567890abcdef0",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "pending",
                "VolumeId": "vol-049df61146c4d7901",
                "VolumeSize": 8,
            },
        ],
    }

    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkCopySnapShotStatus.handler(event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isSnapShotCopyComplete") == False


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_remote_exception():
    event = {
        "Payload": {
            "body": {
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "forensicType": "DISK",
                "snapshotIds": [
                    "snap-097e3ce579357377b",
                    "snap-097e3ce579357377c",
                ],
                "snapshotArtifactMap": {
                    "snap-097e3ce579357377b": "d0b18a74-c2f1-4309-b17d-c8253b01ab29",
                    "snap-097e3ce579357377c": "d0b18a74-c2f1-4309-b17d-c8253b01ab29",
                },
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
            },
            "statusCode": 200,
        }
    }
    describe_snapshot_fn.side_effect = Exception("AWS ERROR!")
    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        checkCopySnapShotStatus.handler(event, context)
        assert execinfo.type == Exception
        update_item_fn.assert_called()
        describe_snapshot_fn.reset_mock()


# New test cases to improve coverage

@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_snapshot_not_shared():
    """Test when isSnapshotShared is False"""
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "snapshotIds": ["snap-097e3ce579357377b"],
                "copySnapshotIds": ["snap-097e3ce579357377c"],
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "snapshotArtifactMap": {
                    "snap-097e3ce579357377b": "d0b18a74-c2f1-4309-b17d-c8253b01ab29"
                },
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": False,
            },
            "statusCode": 200,
        }
    }
    # Reset the side_effect that might have been set by other tests
    describe_snapshot_fn.side_effect = None
    describe_snapshot_fn.return_value = {
        "NextToken": "",
        "Snapshots": [
            {
                "Description": "This is my snapshot.",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-097e3ce579357377b",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "completed",
                "VolumeId": "vol-049df61146c4d7901",
                "VolumeSize": 8,
            },
        ],
    }

    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkCopySnapShotStatus.handler(event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isAppCopySnapShotComplete") == True


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_eks_cluster_scenario():
    """Test EKS cluster scenario with multiple nodes"""
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
                "clusterInfo": {
                    "clusterName": "test-cluster",
                    "affectedNode": ["i-123", "i-456"],
                },
                "snapshotIds": ["snap-123", "snap-456"],
            },
            "statusCode": 200,
        }
    }
    # Reset the side_effect that might have been set by other tests
    describe_snapshot_fn.side_effect = None
    describe_snapshot_fn.return_value = {
        "NextToken": "",
        "Snapshots": [
            {
                "Description": "EKS node snapshot",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-123",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "completed",
                "VolumeId": "vol-123",
                "VolumeSize": 8,
            },
            {
                "Description": "EKS node snapshot",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-456",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "completed",
                "VolumeId": "vol-456",
                "VolumeSize": 8,
            },
        ],
    }

    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkCopySnapShotStatus.handler(event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isSnapShotCopyComplete") == True
        assert "clusterInfo" in ret.get("body")


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_mixed_snapshot_states():
    """Test when some snapshots are completed and others are still pending"""
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "snapshotIds": ["snap-123", "snap-456"],
                "copySnapshotIds": ["snap-789", "snap-abc"],
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
            },
            "statusCode": 200,
        }
    }
    # Reset the side_effect that might have been set by other tests
    describe_snapshot_fn.side_effect = None
    describe_snapshot_fn.return_value = {
        "NextToken": "",
        "Snapshots": [
            {
                "Description": "This is my snapshot.",
                "OwnerId": "123456789012",
                "Progress": "100%",
                "SnapshotId": "snap-123",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "completed",
                "VolumeId": "vol-123",
                "VolumeSize": 8,
            },
            {
                "Description": "This is my snapshot.",
                "OwnerId": "123456789012",
                "Progress": "50%",
                "SnapshotId": "snap-456",
                "StartTime": "2021-11-22T21:14:34.523622",
                "State": "pending",
                "VolumeId": "vol-456",
                "VolumeSize": 8,
            },
        ],
    }

    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkCopySnapShotStatus.handler(event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isSnapShotCopyComplete") == False


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_empty_snapshots_list():
    """Test when the snapshots list is empty"""
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "snapshotIds": [],
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
            },
            "statusCode": 200,
        }
    }
    # Reset the side_effect that might have been set by other tests
    describe_snapshot_fn.side_effect = None
    describe_snapshot_fn.return_value = {
        "NextToken": "",
        "Snapshots": [],
    }

    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkCopySnapShotStatus.handler(event, context)
        assert ret.get("statusCode") == 200
        # An empty list should be considered "complete" since there's nothing to wait for
        assert ret.get("body").get("isSnapShotCopyComplete") == True


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_specific_error_handling():
    """Test specific error handling with DiskAcquisitionError"""
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "isSnapShotComplete": False,
                "isSnapShotCopyComplete": False,
                "snapshotIds": ["snap-123"],
                "instanceAccount": "123456789012",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isSnapshotShared": True,
            },
            "statusCode": 200,
        }
    }
    
    # Simulate a specific AWS error
    describe_snapshot_fn.side_effect = boto3.exceptions.Boto3Error("Snapshot not found")
    
    with patch.object(
        checkCopySnapShotStatus,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        checkCopySnapShotStatus.handler(event, context)
        
        # Verify the error details
        assert "errorName" in execinfo.value.args[0]
        assert "errorDescription" in execinfo.value.args[0]
        assert "errorPhase" in execinfo.value.args[0]
        assert execinfo.value.args[0]["errorPhase"] == ForensicsProcessingPhase.ACQUISITION.name
        assert execinfo.value.args[0]["errorComponentId"] == "checkCopySnapShotStatus"


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "APP_ACCOUNT_COPY": "FALSE",
    },
)
def test_all_snapshots_completed_function():
    """Test the all_snapshots_completed function directly"""
    # Test with all completed snapshots
    snapshots = {
        "Snapshots": [
            {"State": "completed"},
            {"State": "completed"},
            {"State": "completed"}
        ]
    }
    assert checkCopySnapShotStatus.all_snapshots_completed(snapshots) == True
    
    # Test with mixed states
    snapshots = {
        "Snapshots": [
            {"State": "completed"},
            {"State": "pending"},
            {"State": "completed"}
        ]
    }
    assert checkCopySnapShotStatus.all_snapshots_completed(snapshots) == False
    
    # Test with all pending snapshots
    snapshots = {
        "Snapshots": [
            {"State": "pending"},
            {"State": "pending"}
        ]
    }
    assert checkCopySnapShotStatus.all_snapshots_completed(snapshots) == False
    
    # Test with other states
    snapshots = {
        "Snapshots": [
            {"State": "error"},
            {"State": "completed"}
        ]
    }
    assert checkCopySnapShotStatus.all_snapshots_completed(snapshots) == False