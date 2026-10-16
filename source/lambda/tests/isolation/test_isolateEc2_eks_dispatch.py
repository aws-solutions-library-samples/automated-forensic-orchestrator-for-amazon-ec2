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
"""EKS isolation dispatch.

``resource_type == "Pods" or "Deployment" or "ServiceAccount"`` was always
true, so every EKS finding took the pod branch and the Node branch never ran.
These tests pin the dispatch per affected resource type, the handling of
unknown types, and the fail-closed skip when triage could not confirm that
the node belongs to the cluster.
"""

import os
from unittest import mock
from unittest.mock import MagicMock, call, patch

import pytest

from ...src.data.datatypes import ForensicsProcessingPhase, ResourceType
from ...src.isolation import isolateEc2

ENV = {
    "AWS_REGION": "us-east-1",
    "INSTANCE_TABLE_NAME": "t",
    "APP_ACCOUNT_ROLE": "TestRole",
    "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME": "ForensicIsolationProfile",
    "SOLUTION_ACCOUNT_ISOLATION_INSTANCE_PROFILE_NAME": "SolProfile",
}
POD_HELPERS = ("eks_label_pod", "eks_pod_containtment", "eks_cordon_node")
ALL_HELPERS = POD_HELPERS + ("eks_cordon_nodes_by_instance_id",)


def eks_body(resource_type, **overrides):
    cluster_info = {
        "clusterName": "c1",
        "affectedNode": ["i-0abc"],
        "affectedPodResource": ["p1"],
        "affectedResourceNamespace": "ns",
        "affectedResourceType": resource_type,
        "nodeConfirmed": True,
    }
    cluster_info.update(overrides)
    return {
        "forensicId": "fid",
        "instanceAccount": "123456789012",
        "instanceRegion": "us-east-1",
        "instanceInfo": [
            {
                "InstanceId": "i-0abc",
                "VpcId": "vpc-1",
                "SecurityGroups": [{"GroupId": "sg-orig"}],
                "NetworkInterfaces": [
                    {
                        "NetworkInterfaceId": "eni-1",
                        "Groups": [{"GroupId": "sg-orig"}],
                    }
                ],
                "BlockDeviceMappings": [
                    {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1"}}
                ],
            }
        ],
        "clusterInfo": cluster_info,
    }


def eks_record(instance_info=None):
    record = MagicMock()
    record.id = "fid"
    record.resourceType = ResourceType.EKS
    record.resourceInfo = {
        "clusterName": "c1",
        "instanceInfo": instance_info
        or [
            {
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::123456789012:"
                    "instance-profile/node-profile"
                }
            }
        ],
    }
    return record


class Clients:
    def __init__(self):
        self.eks = MagicMock()
        self.iam = MagicMock()
        self.iam.get_instance_profile.return_value = {
            "InstanceProfile": {"Roles": [{"RoleName": "r1"}]}
        }
        self.ec2 = MagicMock()
        self.ec2.describe_addresses.return_value = {"Addresses": []}
        self.ec2.describe_iam_instance_profile_associations.return_value = {
            "IamInstanceProfileAssociations": []
        }
        self.calls = []

    def __call__(self, service, **kwargs):
        self.calls.append(service)
        return {"eks": self.eks, "iam": self.iam, "ec2": self.ec2}.get(
            service, MagicMock()
        )


@pytest.fixture(autouse=True)
def env():
    with mock.patch.dict(os.environ, ENV):
        yield


@pytest.fixture
def fds():
    with patch.object(isolateEc2, "ForensicDataService") as fds_class:
        fds_class.return_value.get_forensic_record.return_value = eks_record()
        yield fds_class.return_value


@pytest.fixture
def clients():
    c = Clients()
    with patch.object(isolateEc2, "create_aws_client", side_effect=c):
        yield c


@pytest.fixture
def helpers():
    patchers = {name: patch.object(isolateEc2, name) for name in ALL_HELPERS}
    mocks = {name: p.start() for name, p in patchers.items()}
    yield mocks
    for p in patchers.values():
        p.stop()


@pytest.fixture
def context():
    ctx = MagicMock()
    ctx.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:654321098765:function:f"
    )
    return ctx


def run(body, context):
    return isolateEc2.handler({"Payload": {"body": body}}, context)


def last_timeline_event(fds):
    return fds.add_forensic_timeline_event.call_args.kwargs


@pytest.mark.parametrize(
    "resource_type", ["Pods", "Deployment", "ServiceAccount"]
)
def test_pod_types_take_the_pod_branch(
    resource_type, fds, clients, helpers, context
):
    result = run(eks_body(resource_type), context)

    assert result["statusCode"] == 200
    for name in POD_HELPERS:
        helpers[name].assert_called_once()
    helpers["eks_cordon_nodes_by_instance_id"].assert_not_called()
    event = last_timeline_event(fds)
    assert event["name"] == f"{resource_type} isolated"
    assert event["phase"] == ForensicsProcessingPhase.ISOLATION


def test_node_type_takes_the_node_branch(fds, clients, helpers, context):
    with patch.object(
        isolateEc2,
        "get_required_isolation_security_groups",
        return_value=("sg-iso", "sg-norule"),
    ):
        result = run(eks_body("Node"), context)

    assert result["statusCode"] == 200
    helpers["eks_cordon_nodes_by_instance_id"].assert_called_once()
    for name in POD_HELPERS:
        helpers[name].assert_not_called()
    clients.ec2.modify_network_interface_attribute.assert_has_calls(
        [
            call(NetworkInterfaceId="eni-1", Groups=["sg-iso"]),
            call(NetworkInterfaceId="eni-1", Groups=["sg-norule"]),
        ]
    )
    clients.ec2.modify_instance_attribute.assert_any_call(
        InstanceId="i-0abc", DisableApiTermination={"Value": True}
    )
    clients.ec2.modify_instance_attribute.assert_any_call(
        InstanceId="i-0abc",
        BlockDeviceMappings=[
            {"DeviceName": "/dev/xvda", "Ebs": {"DeleteOnTermination": False}}
        ],
    )
    clients.iam.get_instance_profile.assert_called_once_with(
        InstanceProfileName="node-profile"
    )
    clients.iam.put_role_policy.assert_called_once()
    event = last_timeline_event(fds)
    assert event["name"] == "Node isolated"
    assert event["phase"] == ForensicsProcessingPhase.ISOLATION


def test_node_cordon_failure_is_recorded_without_revert(
    fds, clients, helpers, context
):
    helpers["eks_cordon_nodes_by_instance_id"].side_effect = Exception("boom")

    result = run(eks_body("Node"), context)

    assert result["statusCode"] == 200
    clients.ec2.modify_instance_attribute.assert_not_called()
    event = last_timeline_event(fds)
    assert event["name"] == "Node isolation failed"
    assert event["phase"] == ForensicsProcessingPhase.ISOLATION_FAILED


@pytest.mark.parametrize("resource_type", ["none", "Foo"])
def test_unknown_type_records_failure_and_isolates_nothing(
    resource_type, fds, clients, helpers, context
):
    result = run(eks_body(resource_type), context)

    assert result["statusCode"] == 200
    for helper in helpers.values():
        helper.assert_not_called()
    clients.ec2.modify_network_interface_attribute.assert_not_called()
    event = last_timeline_event(fds)
    assert event["name"] == f"{resource_type} isolation failed"
    assert event["phase"] == ForensicsProcessingPhase.ISOLATION_FAILED
    assert event["event_data"] == {"affectedResourceType": resource_type}


def test_unconfirmed_node_skips_kubernetes_isolation(
    fds, clients, helpers, context
):
    body = eks_body("Pods", nodeConfirmed=False)

    result = run(body, context)

    assert result["statusCode"] == 200
    assert result["body"] == body
    # Only the DynamoDB client for the forensic record; no target clients.
    assert clients.calls == ["dynamodb"]
    for helper in helpers.values():
        helper.assert_not_called()
    event = last_timeline_event(fds)
    assert event["name"] == "EKS isolation skipped"
    assert event["phase"] == ForensicsProcessingPhase.ISOLATION_FAILED
    assert event["event_data"]["nodeConfirmed"] is False


def test_missing_flag_counts_as_confirmed(fds, clients, helpers, context):
    body = eks_body("Pods")
    del body["clusterInfo"]["nodeConfirmed"]

    run(body, context)

    for name in POD_HELPERS:
        helpers[name].assert_called_once()


def test_cordon_by_instance_id_patches_only_the_schedulable_match():
    page = MagicMock()
    page.metadata._continue = None
    nodes = []
    for name, provider_id, unschedulable in [
        ("a", "aws:///us-east-1a/i-0abc", False),
        ("b", "aws:///us-east-1a/i-0abc", True),
        ("c", "aws:///us-east-1a/i-0zzz", False),
    ]:
        node = MagicMock()
        node.metadata.name = name
        node.spec.provider_id = provider_id
        node.spec.unschedulable = unschedulable
        nodes.append(node)
    page.items = nodes

    with patch.object(isolateEc2, "get_eks_credentials"), patch(
        "kubernetes.config.load_kube_config_from_dict"
    ), patch("kubernetes.client.CoreV1Api") as core_api:
        core_api.return_value.list_node.return_value = page
        isolateEc2.eks_cordon_nodes_by_instance_id(
            eks_body("Node"), MagicMock(), "arn:aws:iam::1:role/r"
        )

    core_api.return_value.patch_node.assert_called_once_with(
        "a", {"spec": {"unschedulable": True}}
    )


def test_credential_revocation_reads_the_eks_node_profile():
    iam = MagicMock()
    iam.get_instance_profile.return_value = {
        "InstanceProfile": {"Roles": [{"RoleName": "r1"}]}
    }

    isolateEc2.invalid_existing_credential_sessions(iam, eks_record())

    iam.get_instance_profile.assert_called_once_with(
        InstanceProfileName="node-profile"
    )


def test_credential_revocation_without_profile_does_nothing():
    iam = MagicMock()

    isolateEc2.invalid_existing_credential_sessions(
        iam, eks_record(instance_info=[{"InstanceId": "i-0abc"}])
    )

    iam.get_instance_profile.assert_not_called()
    iam.put_role_policy.assert_not_called()
