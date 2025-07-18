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
import json
import copy
import datetime
import sys
from unittest import mock
from unittest.mock import MagicMock, Mock, patch, call
import pytest
import botocore
from botocore.exceptions import ClientError

from ...src.isolation import isolateEc2
from ...src.common.exception import ForensicLambdaExecutionException, MemoryAcquisitionError
from ...src.data.datatypes import ForensicsProcessingPhase, ResourceType


class TestIsolateEc2:
    """Test isolateEc2 functionality"""

    @pytest.fixture
    def mock_ec2_client(self):
        """Mock EC2 client"""
        client = MagicMock()
        return client

    @pytest.fixture
    def mock_fds(self):
        """Mock ForensicDataService"""
        fds = MagicMock()
        return fds
        
    @pytest.fixture
    def mock_forensic_record(self):
        """Mock forensic record"""
        record = MagicMock()
        record.id = "test-forensic-id"
        record.resourceId = "i-1234567890abcdef0"
        record.resourceType = ResourceType.INSTANCE
        record.resourceInfo = {
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::123456789012:instance-profile/test-profile",
                "Id": "AIPAYFFB3ORIFIFKOTFH4"
            },
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {
                        "Status": "attached",
                        "VolumeId": "vol-0fa9fbf1a0323a04f",
                        "AttachTime": "2021-11-18T04:58:54+00:00",
                        "DeleteOnTermination": True,
                    }
                }
            ]
        }
        record.memoryAnalysisStatus = ForensicsProcessingPhase.ACQUISITION
        return record

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME": "ForensicIsolationProfile",
        },
    )
    @patch("lambda.src.isolation.isolateEc2.ForensicDataService")
    @patch("lambda.src.isolation.isolateEc2.create_aws_client")
    def test_isolate_ec2_success(self, mock_create_aws_client, mock_fds_class, mock_forensic_record):
        """Test successful EC2 isolation"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-isolation",
                    "GroupName": "Forensic-isolation-convertion-vpc-12345",
                },
                {
                    "GroupId": "sg-isolation-no-rule",
                    "GroupName": "Forensic-isolation-no-rule-vpc-12345",
                }
            ]
        }
        mock_create_aws_client.return_value = mock_ec2_client

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "MEMORY",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "forensicId": "test-forensic-id",
                    "instanceInfo": {
                        "InstanceId": "i-1234567890abcdef0",
                        "VpcId": "vpc-12345",
                        "SecurityGroups": [
                            {"GroupId": "sg-original", "GroupName": "original-sg"}
                        ],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": "eni-12345",
                                "Groups": [
                                    {"GroupId": "sg-original", "GroupName": "original-sg"}
                                ]
                            }
                        ]
                    }
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:654321098765:function:test-function"
        )

        # Call the actual handler
        result = isolateEc2.handler(event, context)

        # Verify results
        assert result["statusCode"] == 200
        
        # Verify the EC2 client was called correctly
        mock_create_aws_client.assert_called()
        mock_ec2_client.modify_network_interface_attribute.assert_called()
        mock_fds_instance.add_forensic_timeline_event.assert_called()

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME": "ForensicIsolationProfile",
        },
    )
    @patch("lambda.src.isolation.isolateEc2.ForensicDataService")
    @patch("lambda.src.isolation.isolateEc2.create_aws_client")
    def test_isolate_ec2_error(self, mock_create_aws_client, mock_fds_class, mock_forensic_record):
        """Test error handling in EC2 isolation"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "DescribeSecurityGroups"
        )
        mock_create_aws_client.return_value = mock_ec2_client

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "MEMORY",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "forensicId": "test-forensic-id",
                    "instanceInfo": {
                        "InstanceId": "i-1234567890abcdef0",
                        "VpcId": "vpc-12345",
                        "SecurityGroups": [
                            {"GroupId": "sg-original", "GroupName": "original-sg"}
                        ],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": "eni-12345",
                                "Groups": [
                                    {"GroupId": "sg-original", "GroupName": "original-sg"}
                                ]
                            }
                        ]
                    }
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:654321098765:function:test-function"
        )

        # Call the handler and expect exception
        with pytest.raises(ClientError) as exc_info:
            isolateEc2.handler(event, context)

        # Verify error handling
        mock_fds_instance.add_forensic_timeline_event.assert_called_with(
            id="test-forensic-id",
            name="Instance isolation failed",
            description="Instance isolated for i-1234567890abcdef0 failed",
            phase=ForensicsProcessingPhase.ISOLATION_FAILED,
            component_id="isolateEc2",
            component_type="Lambda",
            event_data=mock.ANY
        )
        mock_fds_instance.update_forensic_record_phase_status.assert_called()

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME": "ForensicIsolationProfile",
        },
    )
    @patch("lambda.src.isolation.isolateEc2.ForensicDataService")
    @patch("lambda.src.isolation.isolateEc2.create_aws_client")
    @patch("lambda.src.isolation.isolateEc2.eks_cordon_node")
    @patch("lambda.src.isolation.isolateEc2.eks_pod_containtment")
    @patch("lambda.src.isolation.isolateEc2.eks_label_pod")
    def test_isolate_ec2_eks_success(
        self, 
        mock_eks_label_pod,
        mock_eks_pod_containtment,
        mock_eks_cordon_node,
        mock_create_aws_client, 
        mock_fds_class, 
        mock_forensic_record
    ):
        """Test successful EKS isolation"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record
        
        mock_eks_client = MagicMock()
        mock_iam_client = MagicMock()
        mock_ec2_client = MagicMock()
        
        # Configure create_aws_client to return different clients based on service name
        def side_effect(service_name, **kwargs):
            if service_name == "eks":
                return mock_eks_client
            elif service_name == "iam":
                return mock_iam_client
            elif service_name == "ec2":
                return mock_ec2_client
            else:
                return MagicMock()
                
        mock_create_aws_client.side_effect = side_effect

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "MEMORY",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "forensicId": "test-forensic-id",
                    "clusterInfo": {
                        "clusterName": "test-cluster",
                        "affectedNode": ["i-123", "i-456"],
                        "affectedPodResource": ["pod1", "pod2"],
                        "affectedResourceNamespace": "default",
                        "affectedResourceType": "Pods"
                    }
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:654321098765:function:test-function"
        )

        # Call the actual handler
        result = isolateEc2.handler(event, context)

        # Verify results
        assert result["statusCode"] == 200
        
        # Verify the EKS functions were called
        mock_eks_label_pod.assert_called_once()
        mock_eks_pod_containtment.assert_called_once()
        mock_eks_cordon_node.assert_called_once()
        mock_fds_instance.add_forensic_timeline_event.assert_called()

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME": "ForensicIsolationProfile",
        },
    )
    @patch("lambda.src.isolation.isolateEc2.ForensicDataService")
    @patch("lambda.src.isolation.isolateEc2.create_aws_client")
    def test_error_handling_flow(self, mock_create_aws_client, mock_fds_class, mock_forensic_record):
        """Test error handling flow when coming from a previous error"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record
        
        # Create test event for error handling flow with complete instanceInfo
        event = {
            "Error": "MemoryAcquisitionError",
            "Cause": json.dumps({
                "errorMessage": json.dumps({
                    "forensicType": "MEMORY",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "forensicId": "test-forensic-id",
                    "instanceInfo": {
                        "InstanceId": "i-1234567890abcdef0",
                        "VpcId": "vpc-12345",
                        "SecurityGroups": [
                            {"GroupId": "sg-original", "GroupName": "original-sg"}
                        ],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": "eni-12345",
                                "Groups": [
                                    {"GroupId": "sg-original", "GroupName": "original-sg"}
                                ]
                            }
                        ]
                    },
                    "errorName": "MemoryAcquisitionError",
                    "errorDescription": "Failed to acquire memory"
                })
            })
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:654321098765:function:test-function"
        )

        # Mock EC2 client
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-isolation",
                    "GroupName": "Forensic-isolation-convertion-vpc-12345",
                },
                {
                    "GroupId": "sg-isolation-no-rule",
                    "GroupName": "Forensic-isolation-no-rule-vpc-12345",
                }
            ]
        }
        mock_create_aws_client.return_value = mock_ec2_client

        # Call the handler and expect exception
        with pytest.raises(ForensicLambdaExecutionException):
            isolateEc2.handler(event, context)

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
            "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME": "ForensicIsolationProfile",
        },
    )
    @patch("lambda.src.isolation.isolateEc2.ForensicDataService")
    @patch("lambda.src.isolation.isolateEc2.create_aws_client")
    def test_previous_isolation_failed(self, mock_create_aws_client, mock_fds_class):
        """Test when previous isolation has failed"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        
        # Create a forensic record with ISOLATION_FAILED status
        mock_forensic_record = MagicMock()
        mock_forensic_record.id = "test-forensic-id"
        mock_forensic_record.resourceId = "i-1234567890abcdef0"
        mock_forensic_record.resourceType = ResourceType.INSTANCE
        mock_forensic_record.memoryAnalysisStatus = ForensicsProcessingPhase.ISOLATION_FAILED
        
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record

        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "MEMORY",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "forensicId": "test-forensic-id",
                    "instanceInfo": {
                        "InstanceId": "i-1234567890abcdef0",
                        "VpcId": "vpc-12345",
                        "SecurityGroups": [
                            {"GroupId": "sg-original", "GroupName": "original-sg"}
                        ],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": "eni-12345",
                                "Groups": [
                                    {"GroupId": "sg-original", "GroupName": "original-sg"}
                                ]
                            }
                        ]
                    }
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:654321098765:function:test-function"
        )

        # Call the handler and expect exception
        with pytest.raises(ForensicLambdaExecutionException) as exc_info:
            isolateEc2.handler(event, context)
            
        assert "Previous isolation failed" in str(exc_info.value)

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
        },
    )
    @patch("lambda.src.isolation.isolateEc2.ForensicDataService")
    @patch("lambda.src.isolation.isolateEc2.create_aws_client")
    @patch("lambda.src.isolation.isolateEc2.eks_cordon_node")
    def test_eks_isolation_error(
        self, 
        mock_eks_cordon_node,
        mock_create_aws_client, 
        mock_fds_class, 
        mock_forensic_record
    ):
        """Test error handling in EKS isolation"""
        # Setup mocks
        mock_fds_instance = mock_fds_class.return_value
        mock_fds_instance.get_forensic_record.return_value = mock_forensic_record
        
        # Make eks_cordon_node raise an exception
        mock_eks_cordon_node.side_effect = Exception("Failed to cordon node")
        
        # Create test event
        event = {
            "Payload": {
                "body": {
                    "forensicType": "MEMORY",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "forensicId": "test-forensic-id",
                    "clusterInfo": {
                        "clusterName": "test-cluster",
                        "affectedNode": ["i-123", "i-456"],
                        "affectedPodResource": ["pod1", "pod2"],
                        "affectedResourceNamespace": "default",
                        "affectedResourceType": "Node"
                    }
                }
            }
        }

        # Create mock context
        context = MagicMock()
        context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:654321098765:function:test-function"
        )

        # Call the actual handler
        result = isolateEc2.handler(event, context)

        # Verify results
        assert result["statusCode"] == 200
        
        # Verify the error was logged
        mock_fds_instance.add_forensic_timeline_event.assert_called_with(
            id="test-forensic-id",
            name="Node isolation failed",
            description="Node isolation for AwsEKSCluster",
            phase=ForensicsProcessingPhase.ISOLATION_FAILED,
            component_id="isolateEksCluster",
            component_type="Lambda",
            event_data=mock.ANY
        )

    @mock.patch.dict(
        os.environ,
        {
            "AWS_REGION": "us-east-1",
            "INSTANCE_TABLE_NAME": "test-table",
            "APP_ACCOUNT_ROLE": "TestRole",
        },
    )
    def test_get_required_isolation_security_groups(self):
        """Test get_required_isolation_security_groups function"""
        # Create mock EC2 client
        mock_ec2_client = MagicMock()
        
        # Test case 1: Security groups don't exist yet
        mock_ec2_client.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2_client.create_security_group.side_effect = [
            {"GroupId": "sg-isolation"},
            {"GroupId": "sg-isolation-no-rule"}
        ]
        
        # Call the function
        isolation_sg, isolation_sg_no_rule = isolateEc2.get_required_isolation_security_groups(
            mock_ec2_client, "vpc-12345"
        )
        
        # Verify results
        assert isolation_sg == "sg-isolation"
        assert isolation_sg_no_rule == "sg-isolation-no-rule"
        assert mock_ec2_client.create_security_group.call_count == 2
        mock_ec2_client.authorize_security_group_ingress.assert_called_once()
        
        # Test case 2: Security groups already exist
        mock_ec2_client.reset_mock()
        mock_ec2_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-existing-isolation",
                    "GroupName": "Forensic-isolation-convertion-vpc-12345",
                },
                {
                    "GroupId": "sg-existing-no-rule",
                    "GroupName": "Forensic-isolation-no-rule-vpc-12345",
                }
            ]
        }
        
        # Call the function
        isolation_sg, isolation_sg_no_rule = isolateEc2.get_required_isolation_security_groups(
            mock_ec2_client, "vpc-12345"
        )
        
        # Verify results
        assert isolation_sg == "sg-existing-isolation"
        assert isolation_sg_no_rule == "sg-existing-no-rule"
        assert mock_ec2_client.create_security_group.call_count == 0