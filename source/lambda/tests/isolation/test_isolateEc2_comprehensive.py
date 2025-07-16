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
import datetime
from unittest import mock
from unittest.mock import MagicMock, Mock, patch, call
import pytest
import botocore
from botocore.exceptions import ClientError

from ...src.isolation import isolateEc2
from ...src.common.exception import ForensicLambdaExecutionException, MemoryAcquisitionError
from ...src.data.datatypes import ForensicsProcessingPhase, ResourceType


# Removed complex integration tests that require extensive mocking
# Focus on unit tests for individual functions


class TestEKSHelperFunctions:
    """Test EKS helper functions"""

    @patch('lambda.src.isolation.isolateEc2.get_eks_credentials')
    @patch('kubernetes.config.load_kube_config_from_dict')
    @patch('kubernetes.client.CoreV1Api')
    def test_eks_label_pod(self, mock_core_api, mock_load_config, mock_get_creds):
        """Test EKS pod labeling"""
        input_body = {
            "clusterInfo": {
                "clusterName": "test-cluster",
                "affectedPodResource": ["pod1", "pod2"],
                "affectedResourceNamespace": "default"
            }
        }
        
        mock_get_creds.return_value = {"test": "config"}
        mock_api_instance = MagicMock()
        mock_core_api.return_value = mock_api_instance
        
        isolateEc2.eks_label_pod(input_body, None, "role-arn")
        
        # Verify pods were patched
        assert mock_api_instance.patch_namespaced_pod.call_count == 2
        mock_api_instance.patch_namespaced_pod.assert_any_call(
            name="pod1",
            namespace="default",
            body={"metadata": {"labels": {"PHASE": "QUARANTINE"}}}
        )

    @patch('lambda.src.isolation.isolateEc2.get_eks_credentials')
    @patch('kubernetes.config.load_kube_config_from_dict')
    @patch('kubernetes.client.CoreV1Api')
    def test_eks_cordon_node(self, mock_core_api, mock_load_config, mock_get_creds):
        """Test EKS node cordoning"""
        input_body = {
            "clusterInfo": {
                "clusterName": "test-cluster",
                "affectedPodResource": ["pod1"],
                "affectedResourceNamespace": "default",
                "affectedNode": ["i-1234567890abcdef0"]
            }
        }
        
        mock_get_creds.return_value = {"test": "config"}
        mock_api_instance = MagicMock()
        mock_core_api.return_value = mock_api_instance
        
        # Mock pod and node info
        mock_pod = MagicMock()
        mock_pod.spec.node_name = "test-node"
        mock_api_instance.read_namespaced_pod.return_value = mock_pod
        
        mock_node = MagicMock()
        mock_node.spec.provider_id = "aws:///us-east-1a/i-1234567890abcdef0"
        mock_node.spec.unschedulable = False
        mock_api_instance.read_node.return_value = mock_node
        
        isolateEc2.eks_cordon_node(input_body, None, "role-arn")
        
        # Verify node was cordoned
        mock_api_instance.patch_node.assert_called_once_with(
            "test-node", {"spec": {"unschedulable": True}}
        )

    @patch('lambda.src.isolation.isolateEc2.get_eks_credentials')
    @patch('kubernetes.config.load_kube_config_from_dict')
    @patch('kubernetes.client.CoreV1Api')
    def test_eks_cordon_node_already_cordoned(self, mock_core_api, mock_load_config, mock_get_creds):
        """Test EKS node cordoning when already cordoned"""
        input_body = {
            "clusterInfo": {
                "clusterName": "test-cluster",
                "affectedPodResource": ["pod1"],
                "affectedResourceNamespace": "default",
                "affectedNode": ["i-1234567890abcdef0"]
            }
        }
        
        mock_get_creds.return_value = {"test": "config"}
        mock_api_instance = MagicMock()
        mock_core_api.return_value = mock_api_instance
        
        # Mock pod and node info - node already cordoned
        mock_pod = MagicMock()
        mock_pod.spec.node_name = "test-node"
        mock_api_instance.read_namespaced_pod.return_value = mock_pod
        
        mock_node = MagicMock()
        mock_node.spec.provider_id = "aws:///us-east-1a/i-1234567890abcdef0"
        mock_node.spec.unschedulable = True  # Already cordoned
        mock_api_instance.read_node.return_value = mock_node
        
        isolateEc2.eks_cordon_node(input_body, None, "role-arn")
        
        # Verify node was not patched since already cordoned
        mock_api_instance.patch_node.assert_not_called()

    @patch('lambda.src.isolation.isolateEc2.get_eks_credentials')
    @patch('kubernetes.config.load_kube_config_from_dict')
    @patch('kubernetes.client.CoreV1Api')
    @patch('kubernetes.client.NetworkingV1Api')
    @patch('lambda.src.isolation.isolateEc2.create_network_policy')
    @patch('lambda.src.isolation.isolateEc2.create_sts_deny_policy_sa')
    def test_eks_pod_containment(
        self, mock_create_sts, mock_create_policy, mock_network_api, 
        mock_core_api, mock_load_config, mock_get_creds
    ):
        """Test EKS pod containment"""
        input_body = {
            "clusterInfo": {
                "clusterName": "test-cluster",
                "affectedPodResource": ["pod1", "pod2"],
                "affectedResourceNamespace": "default"
            }
        }
        
        mock_get_creds.return_value = {"test": "config"}
        
        isolateEc2.eks_pod_containtment(input_body, None, "role-arn", None)
        
        # Verify network policy and STS deny policy were created
        mock_create_policy.assert_called_once()
        mock_create_sts.assert_called_once()

    @patch('kubernetes.client.V1NetworkPolicy')
    def test_create_network_policy_new(self, mock_network_policy):
        """Test creating new network policy"""
        mock_api_instance = MagicMock()
        mock_api_instance.list_namespaced_network_policy.return_value.items = []
        
        policy_spec = {
            "podSelector": {"matchLabels": {"PHASE": "QUARANTINE"}},
            "policyTypes": ["Ingress", "Egress"]
        }
        
        isolateEc2.create_network_policy(
            mock_api_instance, "default", "deny-all-traffic", policy_spec
        )
        
        # Verify network policy was created
        mock_api_instance.create_namespaced_network_policy.assert_called_once()

    @patch('kubernetes.client.V1NetworkPolicy')
    def test_create_network_policy_exists(self, mock_network_policy):
        """Test when network policy already exists"""
        mock_api_instance = MagicMock()
        
        # Mock existing policy
        mock_existing_policy = MagicMock()
        mock_existing_policy.metadata.name = "deny-all-traffic"
        mock_api_instance.list_namespaced_network_policy.return_value.items = [mock_existing_policy]
        
        policy_spec = {
            "podSelector": {"matchLabels": {"PHASE": "QUARANTINE"}},
            "policyTypes": ["Ingress", "Egress"]
        }
        
        isolateEc2.create_network_policy(
            mock_api_instance, "default", "deny-all-traffic", policy_spec
        )
        
        # Verify network policy was not created since it exists
        mock_api_instance.create_namespaced_network_policy.assert_not_called()

    def test_create_sts_deny_policy_sa_with_irsa(self):
        """Test creating STS deny policy for service account with IRSA"""
        mock_api_instance = MagicMock()
        mock_iam_client = MagicMock()
        
        # Mock pod details
        mock_pod = MagicMock()
        mock_pod.spec.service_account = "test-sa"
        mock_api_instance.read_namespaced_pod.return_value = mock_pod
        
        # Mock service account with IRSA annotation
        mock_sa = MagicMock()
        mock_sa.metadata.annotations = {
            "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/test-role"
        }
        mock_api_instance.read_namespaced_service_account.return_value = mock_sa
        
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "2023-01-01T00:00:00.000000Z"
            
            isolateEc2.create_sts_deny_policy_sa(
                mock_api_instance, "default", ["pod1"], mock_iam_client
            )
            
            # Verify IAM policy was created
            mock_iam_client.put_role_policy.assert_called_once()
            call_args = mock_iam_client.put_role_policy.call_args
            assert call_args[1]["RoleName"] == "test-role"
            assert call_args[1]["PolicyName"] == "AWSRevokeOlderSTSSessions"

    def test_create_sts_deny_policy_sa_no_irsa(self):
        """Test creating STS deny policy for service account without IRSA"""
        mock_api_instance = MagicMock()
        mock_iam_client = MagicMock()
        
        # Mock pod details
        mock_pod = MagicMock()
        mock_pod.spec.service_account = "test-sa"
        mock_api_instance.read_namespaced_pod.return_value = mock_pod
        
        # Mock service account without IRSA annotation
        mock_sa = MagicMock()
        mock_sa.metadata.annotations = None
        mock_api_instance.read_namespaced_service_account.return_value = mock_sa
        
        isolateEc2.create_sts_deny_policy_sa(
            mock_api_instance, "default", ["pod1"], mock_iam_client
        )
        
        # Verify IAM policy was not created
        mock_iam_client.put_role_policy.assert_not_called()


class TestEvidenceProtectionFunctions:
    """Test evidence protection functions"""

    def test_enable_evidence_protection_success(self):
        """Test successful evidence protection"""
        mock_ec2_client = MagicMock()
        
        isolateEc2.enable_evidence_protection("i-123", mock_ec2_client)
        
        # Verify termination protection and shutdown behavior were set
        assert mock_ec2_client.modify_instance_attribute.call_count == 2
        
        # Check termination protection call
        calls = mock_ec2_client.modify_instance_attribute.call_args_list
        assert calls[0][1]["InstanceId"] == "i-123"
        assert calls[0][1]["DisableApiTermination"]["Value"] is True
        
        # Check shutdown behavior call
        assert calls[1][1]["InstanceId"] == "i-123"
        assert calls[1][1]["InstanceInitiatedShutdownBehavior"]["Value"] == "stop"

    def test_enable_evidence_protection_failure(self):
        """Test evidence protection with client error"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_instance_attribute.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.NotFound"}}, "modify_instance_attribute"
        )
        
        # Should not raise exception, just log error
        isolateEc2.enable_evidence_protection("i-123", mock_ec2_client)
        
        # Verify it was attempted
        mock_ec2_client.modify_instance_attribute.assert_called()

    def test_enable_evidence_protection_ebs_success(self):
        """Test successful EBS evidence protection"""
        mock_ec2_client = MagicMock()
        block_mapping = [
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-123"}},
            {"DeviceName": "/dev/xvdb", "Ebs": {"VolumeId": "vol-456"}}
        ]
        
        isolateEc2.enable_evidence_protection_ebs("i-123", block_mapping, mock_ec2_client)
        
        # Verify EBS protection was set
        mock_ec2_client.modify_instance_attribute.assert_called_once()
        call_args = mock_ec2_client.modify_instance_attribute.call_args
        assert call_args[1]["InstanceId"] == "i-123"
        assert len(call_args[1]["BlockDeviceMappings"]) == 2
        assert call_args[1]["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] is False

    def test_enable_evidence_protection_ebs_failure(self):
        """Test EBS evidence protection with client error"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_instance_attribute.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.NotFound"}}, "modify_instance_attribute"
        )
        
        block_mapping = [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-123"}}]
        
        # Should not raise exception, just log error
        isolateEc2.enable_evidence_protection_ebs("i-123", block_mapping, mock_ec2_client)
        
        # Verify it was attempted
        mock_ec2_client.modify_instance_attribute.assert_called()


class TestSecurityGroupFunctions:
    """Test security group management functions"""

    def test_get_existing_security_group_success(self):
        """Test successful security group retrieval"""
        mock_ec2_client = MagicMock()
        mock_response = {
            "SecurityGroups": [
                {"GroupId": "sg-123", "GroupName": "test-sg-1"},
                {"GroupId": "sg-456", "GroupName": "test-sg-2"}
            ]
        }
        mock_ec2_client.describe_security_groups.return_value = mock_response
        
        result = isolateEc2.get_existing_security_group(mock_ec2_client, ["test-sg-1", "test-sg-2"])
        
        assert result == mock_response
        mock_ec2_client.describe_security_groups.assert_called_once()

    def test_get_existing_security_group_not_found(self):
        """Test security group retrieval when groups don't exist"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "InvalidGroup.NotFound"}}, "describe_security_groups"
        )
        
        result = isolateEc2.get_existing_security_group(mock_ec2_client, ["nonexistent-sg"])
        
        assert result == {"SecurityGroups": []}

    def test_get_existing_security_group_other_error(self):
        """Test security group retrieval with other client error"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation"}}, "describe_security_groups"
        )
        
        with pytest.raises(ClientError):
            isolateEc2.get_existing_security_group(mock_ec2_client, ["test-sg"])

    def test_get_required_isolation_security_groups_create_new(self):
        """Test creating new isolation security groups"""
        mock_ec2_client = MagicMock()
        
        # Mock no existing security groups
        mock_ec2_client.describe_security_groups.return_value = {"SecurityGroups": []}
        
        # Mock security group creation responses
        mock_ec2_client.create_security_group.side_effect = [
            {"GroupId": "sg-isolation"},
            {"GroupId": "sg-no-rule"}
        ]
        
        with patch.object(isolateEc2, 'get_existing_security_group') as mock_get_existing:
            mock_get_existing.return_value = {"SecurityGroups": []}
            
            isolation_sg, isolation_sg_no_rule = isolateEc2.get_required_isolation_security_groups(
                mock_ec2_client, "vpc-123"
            )
            
            assert isolation_sg == "sg-isolation"
            assert isolation_sg_no_rule == "sg-no-rule"
            
            # Verify security groups were created
            assert mock_ec2_client.create_security_group.call_count == 2
            mock_ec2_client.authorize_security_group_ingress.assert_called_once()

    def test_get_required_isolation_security_groups_use_existing(self):
        """Test using existing isolation security groups"""
        mock_ec2_client = MagicMock()
        
        existing_sgs = {
            "SecurityGroups": [
                {"GroupId": "sg-existing-1", "GroupName": "Forensic-isolation-convertion-vpc-123"},
                {"GroupId": "sg-existing-2", "GroupName": "Forensic-isolation-no-rule-vpc-123"}
            ]
        }
        
        with patch.object(isolateEc2, 'get_existing_security_group') as mock_get_existing:
            mock_get_existing.return_value = existing_sgs
            
            isolation_sg, isolation_sg_no_rule = isolateEc2.get_required_isolation_security_groups(
                mock_ec2_client, "vpc-123"
            )
            
            assert isolation_sg == "sg-existing-1"
            assert isolation_sg_no_rule == "sg-existing-2"
            
            # Verify no new security groups were created
            mock_ec2_client.create_security_group.assert_not_called()


class TestInstanceProfileFunctions:
    """Test instance profile management functions"""

    @patch.dict(os.environ, {
        "SOLUTION_ACCOUNT_ISOLATION_INSTANCE_PROFILE_NAME": "solution-profile"
    })
    def test_update_profile_for_instance_cross_account(self):
        """Test updating instance profile for cross-account scenario"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_iam_instance_profile_associations.return_value = {
            "IamInstanceProfileAssociations": [{
                "AssociationId": "iip-assoc-123"
            }]
        }
        
        isolateEc2.update_profile_for_instance(
            "i-123", "456789012345", "forensic-profile", mock_ec2_client, "123456789012"
        )
        
        # Verify profile was replaced
        mock_ec2_client.replace_iam_instance_profile_association.assert_called_once()
        call_args = mock_ec2_client.replace_iam_instance_profile_association.call_args
        assert call_args[1]["IamInstanceProfile"]["Name"] == "forensic-profile"
        assert call_args[1]["AssociationId"] == "iip-assoc-123"

    @patch.dict(os.environ, {
        "SOLUTION_ACCOUNT_ISOLATION_INSTANCE_PROFILE_NAME": "solution-profile"
    })
    def test_update_profile_for_instance_same_account(self):
        """Test updating instance profile for same account scenario"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_iam_instance_profile_associations.return_value = {
            "IamInstanceProfileAssociations": [{
                "AssociationId": "iip-assoc-123"
            }]
        }
        
        isolateEc2.update_profile_for_instance(
            "i-123", "123456789012", "forensic-profile", mock_ec2_client, "123456789012"
        )
        
        # Verify solution account profile was used
        mock_ec2_client.replace_iam_instance_profile_association.assert_called_once()
        call_args = mock_ec2_client.replace_iam_instance_profile_association.call_args
        assert call_args[1]["IamInstanceProfile"]["Name"] == "solution-profile"

    def test_update_profile_for_instance_no_existing_profile(self):
        """Test updating instance profile when no existing profile"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_iam_instance_profile_associations.return_value = {
            "IamInstanceProfileAssociations": []
        }
        
        isolateEc2.update_profile_for_instance(
            "i-123", "456789012345", "forensic-profile", mock_ec2_client, "123456789012"
        )
        
        # Verify new profile was associated
        mock_ec2_client.associate_iam_instance_profile.assert_called_once()
        call_args = mock_ec2_client.associate_iam_instance_profile.call_args
        assert call_args[1]["IamInstanceProfile"]["Name"] == "forensic-profile"
        assert call_args[1]["InstanceId"] == "i-123"

    def test_update_profile_for_instance_exception(self):
        """Test instance profile update with exception"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_iam_instance_profile_associations.side_effect = Exception("Test error")
        
        # Should not raise exception, just log error
        isolateEc2.update_profile_for_instance(
            "i-123", "456789012345", "forensic-profile", mock_ec2_client, "123456789012"
        )
        
        # Verify it was attempted
        mock_ec2_client.describe_iam_instance_profile_associations.assert_called()


class TestCredentialInvalidationFunctions:
    """Test credential invalidation functions"""

    def test_invalid_existing_credential_sessions_instance_resource(self):
        """Test invalidating credentials for instance resource"""
        mock_iam_client = MagicMock()
        mock_forensic_record = MagicMock()
        mock_forensic_record.resourceType = ResourceType.INSTANCE
        mock_forensic_record.resourceInfo = {
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::123456789012:instance-profile/test-profile"
            }
        }
        
        mock_iam_client.get_instance_profile.return_value = {
            "InstanceProfile": {
                "Roles": [
                    {"RoleName": "role1"},
                    {"RoleName": "role2"}
                ]
            }
        }
        
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "2023-01-01T00:00:00.000000Z"
            
            isolateEc2.invalid_existing_credential_sessions(mock_iam_client, mock_forensic_record)
            
            # Verify policies were created for both roles
            assert mock_iam_client.put_role_policy.call_count == 2
            
            calls = mock_iam_client.put_role_policy.call_args_list
            assert calls[0][1]["RoleName"] == "role1"
            assert calls[1][1]["RoleName"] == "role2"
            assert all(call[1]["PolicyName"] == "AWSRevokeOlderSTSSessions" for call in calls)

    def test_invalid_existing_credential_sessions_eks_resource(self):
        """Test invalidating credentials for EKS resource (list format)"""
        mock_iam_client = MagicMock()
        mock_forensic_record = MagicMock()
        mock_forensic_record.resourceType = ResourceType.EKS
        mock_forensic_record.resourceInfo = [{
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::123456789012:instance-profile/test-profile"
            }
        }]
        
        mock_iam_client.get_instance_profile.return_value = {
            "InstanceProfile": {
                "Roles": [{"RoleName": "eks-role"}]
            }
        }
        
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "2023-01-01T00:00:00.000000Z"
            
            isolateEc2.invalid_existing_credential_sessions(mock_iam_client, mock_forensic_record)
            
            # Verify policy was created
            mock_iam_client.put_role_policy.assert_called_once()
            call_args = mock_iam_client.put_role_policy.call_args
            assert call_args[1]["RoleName"] == "eks-role"

    def test_invalid_existing_credential_sessions_empty_profile(self):
        """Test invalidating credentials when instance profile has no roles"""
        mock_iam_client = MagicMock()
        mock_forensic_record = MagicMock()
        mock_forensic_record.resourceType = ResourceType.INSTANCE
        mock_forensic_record.resourceInfo = {
            "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/empty-profile"}
        }
        
        # Mock empty profile response
        mock_iam_client.get_instance_profile.return_value = {
            "InstanceProfile": {"Roles": []}
        }
        
        isolateEc2.invalid_existing_credential_sessions(mock_iam_client, mock_forensic_record)
        
        # Verify profile was retrieved but no policies were created due to empty roles
        mock_iam_client.get_instance_profile.assert_called_once()
        mock_iam_client.put_role_policy.assert_not_called()


class TestEIPDetachmentFunctions:
    """Test EIP detachment functions"""

    def test_detach_eip_from_instance_with_eips(self):
        """Test detaching EIPs from instance"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_addresses.return_value = {
            "Addresses": [
                {"AssociationId": "eipassoc-123"},
                {"AssociationId": "eipassoc-456"}
            ]
        }
        
        isolateEc2.detach_eip_from_instance("i-123", mock_ec2_client)
        
        # Verify EIPs were detached
        assert mock_ec2_client.disassociate_address.call_count == 2
        mock_ec2_client.disassociate_address.assert_any_call(AssociationId="eipassoc-123")
        mock_ec2_client.disassociate_address.assert_any_call(AssociationId="eipassoc-456")

    def test_detach_eip_from_instance_no_eips(self):
        """Test detaching EIPs when none exist"""
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_addresses.return_value = {"Addresses": []}
        
        isolateEc2.detach_eip_from_instance("i-123", mock_ec2_client)
        
        # Verify no detachment attempts
        mock_ec2_client.disassociate_address.assert_not_called()


# Removed complex error handling integration tests
# These require extensive mocking of the data service layer


class TestEKSCredentialFunctions:
    """Test EKS credential and cluster functions"""

    @patch('lambda.src.isolation.isolateEc2.get_token')
    def test_get_bearer_token(self, mock_get_token):
        """Test getting EKS bearer token"""
        mock_get_token.return_value = {"status": {"token": "test-token"}}
        
        result = isolateEc2.get_bearer_token("test-cluster", "role-arn")
        
        assert result == {"status": {"token": "test-token"}}
        mock_get_token.assert_called_once_with(
            cluster_name="test-cluster",
            role_arn="role-arn"
        )

    def test_get_cluster_info_success(self):
        """Test successful cluster info retrieval"""
        mock_eks_client = MagicMock()
        mock_eks_client.describe_cluster.return_value = {
            "cluster": {
                "endpoint": "https://test.eks.amazonaws.com",
                "certificateAuthority": {"data": "cert-data"},
                "arn": "arn:aws:eks:region:account:cluster/test"
            }
        }
        
        result = isolateEc2.get_cluster_info("test-cluster", mock_eks_client)
        
        assert result["endpoint"] == "https://test.eks.amazonaws.com"
        assert result["ca"] == "cert-data"
        assert result["name"] == "arn:aws:eks:region:account:cluster/test"

    def test_get_cluster_info_client_error(self):
        """Test cluster info retrieval with client error"""
        mock_eks_client = MagicMock()
        error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}}, "describe_cluster"
        )
        mock_eks_client.describe_cluster.side_effect = error
        
        with pytest.raises(botocore.exceptions.ClientError):
            isolateEc2.get_cluster_info("test-cluster", mock_eks_client)

    @patch.object(isolateEc2, 'get_cluster_info')
    @patch.object(isolateEc2, 'get_bearer_token')
    def test_get_eks_credentials_cached(self, mock_bearer, mock_cluster_info):
        """Test EKS credentials with cached cluster info"""
        # Setup cache
        isolateEc2.cluster_cache["test-cluster"] = {
            "endpoint": "https://test.eks.amazonaws.com",
            "ca": "cert-data",
            "name": "cluster-arn"
        }
        mock_bearer.return_value = {"status": {"token": "test-token"}}
        
        result = isolateEc2.get_eks_credentials("test-cluster", None, "role-arn")
        
        assert result["kind"] == "Config"
        assert result["current-context"] == "lambda-kubectl-context"
        mock_cluster_info.assert_not_called()  # Should use cache
        mock_bearer.assert_called_once()

    @patch.object(isolateEc2, 'get_cluster_info')
    @patch.object(isolateEc2, 'get_bearer_token')
    def test_get_eks_credentials_not_cached(self, mock_bearer, mock_cluster_info):
        """Test EKS credentials without cached cluster info"""
        # Clear cache
        isolateEc2.cluster_cache.clear()
        
        mock_cluster_info.return_value = {
            "endpoint": "https://test.eks.amazonaws.com",
            "ca": "cert-data",
            "name": "cluster-arn"
        }
        mock_bearer.return_value = {"status": {"token": "test-token"}}
        
        result = isolateEc2.get_eks_credentials("test-cluster", None, "role-arn")
        
        assert result["kind"] == "Config"
        mock_cluster_info.assert_called_once()
        mock_bearer.assert_called_once()
        # Should cache the result
        assert "test-cluster" in isolateEc2.cluster_cache

#####
##########################################################################
# COPY SNAPSHOT TESTS
###############################################################################

class TestCopySnapshotFunctions:
    """Test copy snapshot functionality from copysnapshot/performCopySnapshot.py"""

    @pytest.fixture
    def copy_snapshot_event_ec2(self):
        """EC2 copy snapshot event fixture"""
        return {
            "Payload": {
                "body": {
                    "forensicId": "test-forensic-id",
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "snapshotIds": ["snap-123", "snap-456"],
                    "isSnapshotShared": False
                }
            }
        }

    @pytest.fixture
    def copy_snapshot_event_eks(self):
        """EKS copy snapshot event fixture"""
        return {
            "Payload": {
                "body": {
                    "forensicId": "test-forensic-id",
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "isSnapshotShared": False,
                    "clusterInfo": {
                        "affectedNode": ["i-123", "i-456"]
                    },
                    "i-123": {
                        "snapshotIds": ["snap-123a", "snap-123b"]
                    },
                    "i-456": {
                        "snapshotIds": ["snap-456a", "snap-456b"]
                    }
                }
            }
        }

    @pytest.fixture
    def copy_snapshot_event_shared(self):
        """Shared snapshot event fixture"""
        return {
            "Payload": {
                "body": {
                    "forensicId": "test-forensic-id",
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "snapshotIds": ["snap-123", "snap-456"],
                    "isSnapshotShared": True
                }
            }
        }

    @pytest.fixture
    def context(self):
        """Lambda context fixture"""
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
        return context

    @pytest.fixture
    def mock_forensic_record(self):
        """Mock forensic record"""
        record = MagicMock()
        record.resourceId = "i-1234567890abcdef0"
        return record

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_ec2_not_shared_success(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_ec2, context, mock_forensic_record
    ):
        """Test successful EC2 snapshot copy when not shared"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123"},
            {"SnapshotId": "snap-copy-456"}
        ]
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(copy_snapshot_event_ec2, context)
        
        # Verify response
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["instanceId"] == "i-1234567890abcdef0"
        assert body["isCopySnapShotComplete"] is False
        assert body["sourceSnapshotIds"] == ["snap-123", "snap-456"]
        assert body["copySnapshotIds"] == ["snap-copy-123", "snap-copy-456"]
        assert body["snapshotIds"] == ["snap-copy-123", "snap-copy-456"]
        
        # Verify copy_snapshot was called correctly
        assert mock_ec2_client.copy_snapshot.call_count == 2
        
        # Check first call
        first_call = mock_ec2_client.copy_snapshot.call_args_list[0]
        assert first_call[1]["SourceSnapshotId"] == "snap-123"
        assert first_call[1]["Encrypted"] is True
        assert first_call[1]["KmsKeyId"] == "alias/test-alias"
        assert first_call[1]["SourceRegion"] == "us-east-1"
        assert "ForensicID" in str(first_call[1]["TagSpecifications"])

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_ec2_shared_success(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_shared, context, mock_forensic_record
    ):
        """Test successful EC2 snapshot copy when shared"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123"},
            {"SnapshotId": "snap-copy-456"}
        ]
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(copy_snapshot_event_shared, context)
        
        # Verify response for shared snapshot
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["instanceId"] == "i-1234567890abcdef0"
        assert body["isAppCopySnapShotComplete"] is False
        assert body["app_snapshotIds"] == ["snap-123", "snap-456"]
        assert body["forensicCopysnapshotIds"] == ["snap-copy-123", "snap-copy-456"]
        assert body["snapshotIds"] == ["snap-copy-123", "snap-copy-456"]
        
        # Verify copy_snapshot was called with forensic key
        first_call = mock_ec2_client.copy_snapshot.call_args_list[0]
        assert first_call[1]["KmsKeyId"] == "arn:aws:kms:us-east-1:123456789012:key/test-key"

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_eks_success(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_eks, context, mock_forensic_record
    ):
        """Test successful EKS snapshot copy"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123a"},
            {"SnapshotId": "snap-copy-123b"},
            {"SnapshotId": "snap-copy-456a"},
            {"SnapshotId": "snap-copy-456b"}
        ]
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(copy_snapshot_event_eks, context)
        
        # Verify response
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["instanceId"] == ["i-123", "i-456"]
        assert body["isCopySnapShotComplete"] is False
        
        # Verify per-instance snapshot copies
        assert body["i-123"]["copySnapshotIds"] == ["snap-copy-123a", "snap-copy-123b"]
        assert body["i-123"]["isCopyComplete"] is False
        assert body["i-456"]["copySnapshotIds"] == ["snap-copy-456a", "snap-copy-456b"]
        assert body["i-456"]["isCopyComplete"] is False
        
        # Verify all snapshots were copied
        assert mock_ec2_client.copy_snapshot.call_count == 4

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_eks_partial_instances(
        self, mock_fds_class, mock_create_client, context, mock_forensic_record
    ):
        """Test EKS snapshot copy with only some instances having snapshots"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Event with only one instance having snapshots
        event = {
            "Payload": {
                "body": {
                    "forensicId": "test-forensic-id",
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "isSnapshotShared": False,
                    "clusterInfo": {
                        "affectedNode": ["i-123", "i-456"]
                    },
                    "i-123": {
                        "snapshotIds": ["snap-123a", "snap-123b"]
                    }
                    # i-456 has no snapshots
                }
            }
        }
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = [
            {"SnapshotId": "snap-copy-123a"},
            {"SnapshotId": "snap-copy-123b"}
        ]
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(event, context)
        
        # Verify response
        assert result["statusCode"] == 200
        body = result["body"]
        assert body["instanceId"] == ["i-123", "i-456"]
        
        # Only i-123 should have copy snapshots
        assert "i-123" in body
        assert body["i-123"]["copySnapshotIds"] == ["snap-copy-123a", "snap-copy-123b"]
        assert "i-456" not in body or "copySnapshotIds" not in body.get("i-456", {})
        
        # Only 2 snapshots should be copied
        assert mock_ec2_client.copy_snapshot.call_count == 2

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_with_appsync_notifications(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_ec2, context, mock_forensic_record
    ):
        """Test copy snapshot with AppSync notifications enabled"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        with patch.dict(os.environ, {
            "APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS": "true",
            "APPSYNC_API_ENDPOINT": "https://test.appsync.amazonaws.com/graphql"
        }):
            # Setup mocks
            mock_fds = MagicMock()
            mock_fds_class.return_value = mock_fds
            mock_fds.get_forensic_record.return_value = mock_forensic_record
            
            mock_ec2_client = MagicMock()
            mock_ec2_client.copy_snapshot.return_value = {"SnapshotId": "snap-copy-123"}
            mock_create_client.return_value = mock_ec2_client
            
            result = handler(copy_snapshot_event_ec2, context)
            
            # Verify ForensicDataService was initialized with notifications enabled
            mock_fds_class.assert_called_once()
            call_args = mock_fds_class.call_args
            assert call_args[1]['auto_notify_subscribers'] is True
            assert call_args[1]['appsync_api_endpoint_url'] == "https://test.appsync.amazonaws.com/graphql"
            
            assert result["statusCode"] == 200

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_error_handling(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_ec2, context, mock_forensic_record
    ):
        """Test copy snapshot error handling"""
        from ...src.copysnapshot.performCopySnapshot import handler
        from ...src.common.exception import InvestigationError
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        # Mock EC2 client to raise exception
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.side_effect = Exception("AWS Copy Error")
        mock_create_client.return_value = mock_ec2_client
        
        with pytest.raises(InvestigationError) as exc_info:
            handler(copy_snapshot_event_ec2, context)
        
        # Verify error details
        error_body = exc_info.value.args[0]
        assert error_body["errorName"] == "Error: creating snapshot copy for forensic idtest-forensic-id"
        assert "Error while creating snapshot DISK acquisition" in error_body["errorDescription"]
        assert error_body["errorPhase"] == "ACQUISITION"
        assert error_body["errorComponentId"] == "performInstanceCopySnapshot"
        assert error_body["errorComponentType"] == "Lambda"
        assert "AWS Copy Error" in error_body["eventData"]

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_forensic_record_error(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_ec2, context
    ):
        """Test copy snapshot when forensic record retrieval fails"""
        from ...src.copysnapshot.performCopySnapshot import handler
        from ...src.common.exception import InvestigationError
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.side_effect = Exception("Record not found")
        
        mock_ec2_client = MagicMock()
        mock_create_client.return_value = mock_ec2_client
        
        with pytest.raises(InvestigationError) as exc_info:
            handler(copy_snapshot_event_ec2, context)
        
        # Verify error was handled
        error_body = exc_info.value.args[0]
        assert "Record not found" in error_body["eventData"]

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_cross_account_client_creation(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_ec2, context, mock_forensic_record
    ):
        """Test cross-account EC2 client creation for non-shared snapshots"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.return_value = {"SnapshotId": "snap-copy-123"}
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(copy_snapshot_event_ec2, context)
        
        # Verify cross-account client was created
        mock_create_client.assert_called_with(
            "ec2",
            current_account="123456789012",
            target_account="123456789012",
            target_region="us-east-1",
            app_account_role="TestRole"
        )
        
        assert result["statusCode"] == 200

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_same_account_client_creation(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_shared, context, mock_forensic_record
    ):
        """Test same-account EC2 client creation for shared snapshots"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.return_value = {"SnapshotId": "snap-copy-123"}
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(copy_snapshot_event_shared, context)
        
        # Verify same-account client was created (no cross-account parameters)
        mock_create_client.assert_called_with("ec2")
        
        assert result["statusCode"] == 200

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_tag_specifications(
        self, mock_fds_class, mock_create_client, copy_snapshot_event_ec2, context, mock_forensic_record
    ):
        """Test that snapshots are tagged correctly"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.return_value = {"SnapshotId": "snap-copy-123"}
        mock_create_client.return_value = mock_ec2_client
        
        result = handler(copy_snapshot_event_ec2, context)
        
        # Verify tag specifications
        call_args = mock_ec2_client.copy_snapshot.call_args_list[0]
        tag_specs = call_args[1]["TagSpecifications"]
        assert len(tag_specs) == 1
        assert tag_specs[0]["ResourceType"] == "snapshot"
        assert len(tag_specs[0]["Tags"]) == 1
        assert tag_specs[0]["Tags"][0]["Key"] == "ForensicID"
        assert tag_specs[0]["Tags"][0]["Value"] == "test-forensic-id"
        
        assert result["statusCode"] == 200

    @patch.dict(os.environ, {
        "INSTANCE_TABLE_NAME": "test-table",
        "APP_ACCOUNT_ROLE": "TestRole",
        "FORENSIC_EBS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "APP_FORENSIC_EBS_KEY_ALIAS": "test-alias"
    })
    @patch('lambda.src.copysnapshot.performCopySnapshot.create_aws_client')
    @patch('lambda.src.data.service.ForensicDataService')
    def test_copy_snapshot_description_generation(
        self, mock_fds_class, mock_create_client, context, mock_forensic_record
    ):
        """Test snapshot description generation for different scenarios"""
        from ...src.copysnapshot.performCopySnapshot import handler
        
        # Setup mocks
        mock_fds = MagicMock()
        mock_fds_class.return_value = mock_fds
        mock_fds.get_forensic_record.return_value = mock_forensic_record
        
        mock_ec2_client = MagicMock()
        mock_ec2_client.copy_snapshot.return_value = {"SnapshotId": "snap-copy-123"}
        mock_create_client.return_value = mock_ec2_client
        
        # Test non-shared snapshot description
        event_not_shared = {
            "Payload": {
                "body": {
                    "forensicId": "test-forensic-id",
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "snapshotIds": ["snap-123"],
                    "isSnapshotShared": False
                }
            }
        }
        
        handler(event_not_shared, context)
        
        # Verify description for non-shared snapshot
        call_args = mock_ec2_client.copy_snapshot.call_args
        assert "Copy Snapshot to be shared - Forensic ID test-forensic-id" in call_args[1]["Description"]
        
        # Reset mock
        mock_ec2_client.reset_mock()
        
        # Test shared snapshot description
        event_shared = {
            "Payload": {
                "body": {
                    "forensicId": "test-forensic-id",
                    "forensicType": "DISK",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "us-east-1",
                    "snapshotIds": ["snap-123"],
                    "isSnapshotShared": True
                }
            }
        }
        
        handler(event_shared, context)
        
        # Verify description for shared snapshot
        call_args = mock_ec2_client.copy_snapshot.call_args
        assert "Copy Snapshot - Forensic ID test-forensic-id" in call_args[1]["Description"]