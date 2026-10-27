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
"""Triage of GuardDuty Runtime Monitoring findings on EKS.

A Runtime Monitoring finding on an EKS workload carries two resources: the
EC2 node the process ran on and the EKS cluster. Triage used to reject every
such finding as "more than one instance or EKS cluster". It now takes the EKS
path with the node pinned from the finding, confirms the node belongs to the
cluster (tag, else Kubernetes API), and records whether it did so isolation
can fail closed.

The fixture is the real failing event, with the account id replaced.
"""

import copy
import json
import os
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import botocore
import pytest
from kubernetes.client.exceptions import ApiException

from ...src.data.datatypes import ResourceType
from ...src.triage import app

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "test_json_data"
    / "guardduty-eks-runtime-fileless-execution.json"
)
INSTANCE_ID = "i-07846925b8dd4ff42"
CLUSTER = "anycorp-customer-services-eks"
POD = "ticket-application-558f75d74f-kkbl6"
ACCOUNT = "111122223333"
EKS_ARN = f"arn:aws:eks:us-east-1:{ACCOUNT}:cluster/{CLUSTER}"
EC2_ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{INSTANCE_ID}"

_RAW_EVENT = json.loads(FIXTURE.read_text())


@pytest.fixture
def event():
    # The handler mutates the event, so every test gets its own copy.
    return copy.deepcopy(_RAW_EVENT)


@pytest.fixture(autouse=True)
def clear_cluster_cache():
    app.cluster_cache.clear()
    yield
    app.cluster_cache.clear()


def resources(event):
    return event["detail"]["findings"][0]["Resources"]


def ec2_resource(event):
    return next(r for r in resources(event) if r["Type"] == "AwsEc2Instance")


def eks_resource(event):
    return next(r for r in resources(event) if r["Type"] == "AwsEksCluster")


def make_node(provider_id, name="node-1", unschedulable=False):
    node = MagicMock()
    node.spec.provider_id = provider_id
    node.spec.unschedulable = unschedulable
    node.metadata.name = name
    return node


def node_page(nodes, continue_token=None):
    page = MagicMock()
    page.items = nodes
    page.metadata._continue = continue_token
    return page


def single_ec2_event():
    return {
        "resources": [
            "arn:aws:securityhub:us-east-1:"
            f"{ACCOUNT}:action/custom/ForensicTriageAction"
        ],
        "detail": {
            "findings": [
                {
                    "ProductName": "GuardDuty",
                    "GeneratorId": "gen-1",
                    "Region": "us-east-1",
                    "AwsAccountId": ACCOUNT,
                    "Resources": [{"Type": "AwsEc2Instance", "Id": EC2_ARN}],
                }
            ]
        },
    }


def single_eks_audit_event(username="system:serviceaccount:default:sa1"):
    return {
        "resources": [
            "arn:aws:securityhub:us-east-1:"
            f"{ACCOUNT}:action/custom/ForensicTriageAction"
        ],
        "detail": {
            "findings": [
                {
                    "ProductName": "GuardDuty",
                    "GeneratorId": "gen-1",
                    "Region": "us-east-1",
                    "AwsAccountId": ACCOUNT,
                    "Resources": [
                        {
                            "Type": "AwsEksCluster",
                            "Id": EKS_ARN,
                            "Details": {
                                "Other": {
                                    "kubernetesDetails/kubernetesUserDetails"
                                    "/username": username
                                }
                            },
                        }
                    ],
                }
            ]
        },
    }


def instance_description(instance_id=INSTANCE_ID, tags=None):
    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": instance_id,
                        "Tags": tags or [{"Key": "Name", "Value": "node"}],
                        "VpcId": "vpc-1",
                        "SecurityGroups": [{"GroupId": "sg-1"}],
                        "NetworkInterfaces": [
                            {
                                "NetworkInterfaceId": "eni-1",
                                "Groups": [{"GroupId": "sg-1"}],
                            }
                        ],
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/xvda",
                                "Ebs": {"VolumeId": "vol-1"},
                            }
                        ],
                    }
                ]
            }
        ]
    }


class AwsClients:
    """Per-service MagicMocks standing in for create_aws_client."""

    def __init__(self, instance_id=INSTANCE_ID, instance_tags=None):
        self.eks = MagicMock()
        self.eks.describe_cluster.return_value = {
            "cluster": {
                "accessConfig": {"authenticationMode": "API"},
                "endpoint": "https://x",
                "certificateAuthority": {"data": "c"},
                "arn": "arn",
            }
        }
        self.eks.list_access_entries.return_value = {
            "accessEntries": [
                f"arn:aws:iam::{ACCOUNT}:role/ForensicEc2AllowAccessRole"
            ]
        }
        self.ec2 = MagicMock()
        self.ec2.describe_instances.return_value = instance_description(
            instance_id, instance_tags
        )
        self.ssm = MagicMock()
        self.ssm.get_paginator.return_value.paginate.return_value = [
            {
                "InstanceInformationList": [
                    {
                        "InstanceId": instance_id,
                        "PlatformType": "Linux",
                        "PlatformName": "Amazon Linux",
                        "PlatformVersion": "2023",
                    }
                ]
            }
        ]

    def __call__(self, service, **kwargs):
        return {"eks": self.eks, "ec2": self.ec2, "ssm": self.ssm}.get(
            service, MagicMock()
        )


@pytest.fixture
def context():
    ctx = MagicMock()
    ctx.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:444455556666:function:Fo-triage"
    )
    return ctx


@pytest.fixture
def env():
    with mock.patch.dict(
        os.environ,
        {
            "INSTANCE_TABLE_NAME": "table",
            "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        },
    ):
        yield


@pytest.fixture
def fds():
    with patch.object(app, "ForensicDataService") as fds_class:
        yield fds_class.return_value


@pytest.fixture
def core_api():
    with patch("kubernetes.config.load_kube_config_from_dict"), patch(
        "kubernetes.client.CoreV1Api"
    ) as core_api_class, patch.object(
        app, "get_bearer_token", return_value={"status": {"token": "t"}}
    ):
        yield core_api_class


def timeline_names(fds):
    return [
        c.kwargs.get("name")
        for c in fds.add_forensic_timeline_event.call_args_list
    ]


def timeline_event(fds, name):
    return next(
        c.kwargs
        for c in fds.add_forensic_timeline_event.call_args_list
        if c.kwargs.get("name") == name
    )


def run_handler(event, context, clients):
    with patch.object(app, "create_aws_client", side_effect=clients):
        return app.lambda_handler(event, context)


class TestScopeClassification:
    def test_runtime_finding_with_node_and_cluster_is_eks(self, event):
        assert app.is_ec2_or_eks_in_scope(event) == "AwsEksCluster"

    def test_single_ec2_is_ec2(self):
        assert (
            app.is_ec2_or_eks_in_scope(single_ec2_event()) == "AwsEc2Instance"
        )

    def test_unrelated_resources_are_ignored(self):
        # The old loop removed items from the list it was iterating, which
        # skipped elements. Unrelated resources must simply not count.
        ev = single_ec2_event()
        resources(ev).append(
            {"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::bucket"}
        )
        assert app.is_ec2_or_eks_in_scope(ev) == "AwsEc2Instance"

    def test_single_eks_audit_finding_is_eks(self):
        assert (
            app.is_ec2_or_eks_in_scope(single_eks_audit_event())
            == "AwsEksCluster"
        )

    @pytest.mark.parametrize(
        "extra",
        [
            [{"Type": "AwsEc2Instance", "Id": EC2_ARN + "x"}],
            [{"Type": "AwsEksCluster", "Id": EKS_ARN + "-2"}],
        ],
        ids=["two-ec2", "two-eks"],
    )
    def test_two_of_a_type_fails_closed(self, event, extra):
        resources(event).extend(extra)
        with pytest.raises(
            ValueError, match="More than one instance or EKS cluster"
        ):
            app.is_ec2_or_eks_in_scope(event)

    def test_two_ec2_without_eks_fails_closed(self):
        ev = single_ec2_event()
        resources(ev).append({"Type": "AwsEc2Instance", "Id": EC2_ARN + "x"})
        with pytest.raises(ValueError, match="ec2=2, eks=0"):
            app.is_ec2_or_eks_in_scope(ev)

    def test_two_eks_without_ec2_fails_closed(self):
        ev = single_eks_audit_event()
        resources(ev).append({"Type": "AwsEksCluster", "Id": EKS_ARN + "2"})
        with pytest.raises(ValueError, match="ec2=0, eks=2"):
            app.is_ec2_or_eks_in_scope(ev)

    def test_account_mismatch_fails_closed(self, event):
        eks_resource(event)["Id"] = EKS_ARN.replace(ACCOUNT, "777788889999")
        with pytest.raises(ValueError, match="different accounts or regions"):
            app.is_ec2_or_eks_in_scope(event)

    def test_region_mismatch_fails_closed(self, event):
        eks_resource(event)["Id"] = EKS_ARN.replace("us-east-1", "us-west-2")
        with pytest.raises(ValueError, match="different accounts or regions"):
            app.is_ec2_or_eks_in_scope(event)

    def test_pair_split_across_findings_fails_closed(self, event):
        finding = event["detail"]["findings"][0]
        second = copy.deepcopy(finding)
        finding["Resources"] = [ec2_resource(event)]
        second["Resources"] = [
            r for r in second["Resources"] if r["Type"] == "AwsEksCluster"
        ]
        event["detail"]["findings"].append(second)
        with pytest.raises(ValueError, match="same finding"):
            app.is_ec2_or_eks_in_scope(event)

    def test_unparseable_arn_fails_closed(self, event):
        ec2_resource(event)["Id"] = "not-an-arn"
        with pytest.raises(
            ValueError, match="Cannot determine account and region"
        ):
            app.is_ec2_or_eks_in_scope(event)

    def test_no_ec2_or_eks_fails_closed(self):
        ev = single_ec2_event()
        resources(ev)[0] = {"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::b"}
        with pytest.raises(ValueError, match="No EC2 instance or EKS cluster"):
            app.is_ec2_or_eks_in_scope(ev)


class TestPinnedNode:
    def test_pinned_node_is_the_ec2_resource(self, event):
        pinned = app.get_pinned_node(event)
        assert pinned["instanceId"] == INSTANCE_ID
        assert pinned["tags"]["aws:eks:cluster-name"] == CLUSTER

    def test_no_pinned_node_for_single_eks(self):
        assert app.get_pinned_node(single_eks_audit_event()) is None

    @pytest.mark.parametrize(
        "tags,expected",
        [
            ({"aws:eks:cluster-name": CLUSTER}, True),
            ({"eks:cluster-name": CLUSTER}, True),
            ({f"kubernetes.io/cluster/{CLUSTER}": "owned"}, True),
            ({"aws:eks:cluster-name": "other"}, False),
            ({}, False),
            (None, False),
            ([{"Key": "eks:cluster-name", "Value": CLUSTER}], False),
        ],
    )
    def test_is_node_tagged_for_cluster(self, tags, expected):
        assert app.is_node_tagged_for_cluster(tags, CLUSTER) is expected


class TestConfirmNodeInCluster:
    def confirm(self, eks_client=None):
        return app.confirm_node_in_cluster(
            CLUSTER,
            INSTANCE_ID,
            eks_client or AwsClients().eks,
            "arn:aws:iam::111122223333:role/r",
        )

    def test_matching_provider_id_confirms(self, core_api):
        core_api.return_value.list_node.return_value = node_page(
            [make_node(f"aws:///us-east-1a/{INSTANCE_ID}")]
        )
        assert self.confirm() is True

    @pytest.mark.parametrize(
        "provider_id",
        ["aws:///us-east-1a/i-0other", f"aws:///us-east-1a/{INSTANCE_ID}x"],
    )
    def test_non_matching_provider_id_does_not_confirm(
        self, core_api, provider_id
    ):
        core_api.return_value.list_node.return_value = node_page(
            [make_node(provider_id)]
        )
        assert self.confirm() is False

    def test_match_on_second_page_confirms(self, core_api):
        list_node = core_api.return_value.list_node
        list_node.side_effect = [
            node_page([make_node("aws:///us-east-1a/i-0other")], "tok"),
            node_page([make_node(f"aws:///us-east-1a/{INSTANCE_ID}")]),
        ]
        assert self.confirm() is True
        assert list_node.call_count == 2
        assert list_node.call_args_list[1].kwargs["_continue"] == "tok"

    def test_kubernetes_api_error_does_not_confirm(self, core_api):
        core_api.return_value.list_node.side_effect = ApiException(status=403)
        assert self.confirm() is False

    def test_credentials_error_does_not_confirm(self, core_api):
        eks_client = MagicMock()
        eks_client.describe_cluster.side_effect = (
            botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}},
                "DescribeCluster",
            )
        )
        assert self.confirm(eks_client) is False

    def test_node_without_provider_id_is_skipped(self, core_api):
        core_api.return_value.list_node.return_value = node_page(
            [make_node(None), make_node(f"aws:///us-east-1a/{INSTANCE_ID}")]
        )
        assert self.confirm() is True


class TestConfirmPinnedNode:
    def confirm(self, tags):
        return app.confirm_pinned_node(
            {"instanceId": INSTANCE_ID, "tags": tags},
            CLUSTER,
            AwsClients().eks,
            "arn:aws:iam::111122223333:role/r",
        )

    def test_tag_match_skips_kubernetes(self, core_api):
        assert self.confirm({"aws:eks:cluster-name": CLUSTER}) == (
            True,
            "tag",
        )
        core_api.assert_not_called()

    def test_kubernetes_match_without_tags(self, core_api):
        core_api.return_value.list_node.return_value = node_page(
            [make_node(f"aws:///us-east-1a/{INSTANCE_ID}")]
        )
        assert self.confirm({}) == (True, "kubernetes-api")

    def test_unconfirmed_without_tags_or_match(self, core_api):
        core_api.return_value.list_node.return_value = node_page([])
        assert self.confirm({}) == (False, "unconfirmed")


class TestRuntimePodParsing:
    @pytest.fixture(autouse=True)
    def no_pod_lookup(self):
        with patch.object(app, "get_affected_pods") as get_affected_pods:
            yield
            get_affected_pods.assert_not_called()

    def parse(self, ev):
        return app.get_affected_resource_in_cluster(
            ev, CLUSTER, MagicMock(), "arn:aws:iam::111122223333:role/r"
        )

    def test_runtime_finding_names_the_pod(self, event):
        # EC2 is Resources[0]; the EKS resource must be found by type.
        assert resources(event)[0]["Type"] == "AwsEc2Instance"
        assert self.parse(event) == ("Pods", "ticketing", [POD])

    def test_empty_user_details_take_the_workload_path(self):
        ev = single_eks_audit_event()
        resources(ev)[0]["Details"]["Other"] = {
            "kubernetesDetails/kubernetesUserDetails": "",
            "kubernetesDetails/kubernetesWorkloadDetails/type": "pods",
            "kubernetesDetails/kubernetesWorkloadDetails/name": "p1",
            "kubernetesDetails/kubernetesWorkloadDetails/namespace": "ns",
        }
        assert self.parse(ev) == ("Pods", "ns", ["p1"])

    def test_no_workload_details_is_none(self):
        ev = single_eks_audit_event()
        resources(ev)[0]["Details"]["Other"] = {
            "kubernetesDetails/kubernetesUserDetails": ""
        }
        assert self.parse(ev) == ("none", "none", [])


@pytest.mark.usefixtures("env")
class TestHandler:
    def strip_node_tags(self, event):
        ec2_resource(event).pop("Tags", None)

    def test_runtime_finding_pins_the_node(
        self, event, context, fds, core_api
    ):
        with patch.object(app, "get_affected_node_from_pod") as lookup:
            result = run_handler(event, context, AwsClients())
            lookup.assert_not_called()

        assert result["statusCode"] == 200
        body = result["body"]
        cluster_info = body["clusterInfo"]
        assert cluster_info["affectedNode"] == [INSTANCE_ID]
        assert cluster_info["affectedPodResource"] == [POD]
        assert cluster_info["affectedResourceNamespace"] == "ticketing"
        assert cluster_info["affectedResourceType"] == "Pods"
        assert cluster_info["nodeConfirmed"] is True
        assert cluster_info["clusterName"] == CLUSTER
        assert body["isAcquisitionRequired"] == {INSTANCE_ID: True}
        assert body["instanceAccount"] == ACCOUNT
        assert body["instanceRegion"] == "us-east-1"
        assert body["instanceInfo"][0]["InstanceId"] == INSTANCE_ID

        create = fds.create_forensic_record.call_args.kwargs
        assert create["resource_type"] == ResourceType.EKS
        assert create["resource_id"] == [INSTANCE_ID]
        # Tag shortcut: the Kubernetes API is not asked about the node.
        core_api.return_value.list_node.assert_not_called()
        pinned = timeline_event(fds, "EKS node pinned from finding")
        assert pinned["event_data"]["confirmationMethod"] == "tag"

    def test_untagged_node_confirmed_by_kubernetes(
        self, event, context, fds, core_api
    ):
        self.strip_node_tags(event)
        core_api.return_value.list_node.return_value = node_page(
            [make_node(f"aws:///us-east-1a/{INSTANCE_ID}")]
        )
        result = run_handler(event, context, AwsClients())
        assert result["body"]["clusterInfo"]["nodeConfirmed"] is True
        pinned = timeline_event(fds, "EKS node pinned from finding")
        assert pinned["event_data"]["confirmationMethod"] == "kubernetes-api"

    def test_unconfirmed_node_is_still_captured(
        self, event, context, fds, core_api
    ):
        self.strip_node_tags(event)
        core_api.return_value.list_node.return_value = node_page(
            [make_node("aws:///us-east-1a/i-0other")]
        )
        result = run_handler(event, context, AwsClients())

        assert result["statusCode"] == 200
        body = result["body"]
        assert body["clusterInfo"]["nodeConfirmed"] is False
        assert body["clusterInfo"]["affectedNode"] == [INSTANCE_ID]
        assert body["isAcquisitionRequired"] == {INSTANCE_ID: True}
        warning = timeline_event(fds, "Warning: EKS node not confirmed")
        assert warning["event_data"]["nodeConfirmed"] is False
        assert warning["event_data"]["confirmationMethod"] == "unconfirmed"

    def test_kubernetes_error_leaves_node_unconfirmed(
        self, event, context, fds, core_api
    ):
        self.strip_node_tags(event)
        core_api.return_value.list_node.side_effect = ApiException(status=500)
        result = run_handler(event, context, AwsClients())
        assert result["statusCode"] == 200
        assert result["body"]["clusterInfo"]["nodeConfirmed"] is False

    def test_is_triage_required_tag_still_applies(
        self, event, context, fds, core_api
    ):
        clients = AwsClients(
            instance_tags=[{"Key": "IsTriageRequired", "Value": "False"}]
        )
        result = run_handler(event, context, clients)
        assert result["body"]["isAcquisitionRequired"] == {INSTANCE_ID: False}

    def test_account_mismatch_fails_the_triage(
        self, event, context, fds, core_api
    ):
        eks_resource(event)["Id"] = EKS_ARN.replace(ACCOUNT, "777788889999")
        with pytest.raises(ValueError, match="different accounts or regions"):
            run_handler(event, context, AwsClients())
        fds.create_failed_forensic_record.assert_called_once()
        fds.create_forensic_record.assert_not_called()

    def test_audit_log_service_account_finding_unchanged(
        self, context, fds, core_api
    ):
        with patch.object(
            app, "get_affected_pods", return_value=["p1"]
        ), patch.object(
            app, "get_affected_node_from_pod", return_value=["i-0aaa"]
        ) as lookup:
            result = run_handler(
                single_eks_audit_event(),
                context,
                AwsClients(instance_id="i-0aaa"),
            )
            lookup.assert_called_once()

        assert result["statusCode"] == 200
        cluster_info = result["body"]["clusterInfo"]
        assert cluster_info["affectedNode"] == ["i-0aaa"]
        assert cluster_info["affectedResourceType"] == "ServiceAccount"
        assert cluster_info["nodeConfirmed"] is True
        assert "EKS node pinned from finding" not in timeline_names(fds)

    def test_single_ec2_finding_unchanged(self, context, fds, core_api):
        result = run_handler(single_ec2_event(), context, AwsClients())
        assert result["statusCode"] == 200
        assert "clusterInfo" not in result["body"]
        assert result["body"]["instanceInfo"]["InstanceId"] == INSTANCE_ID
        create = fds.create_forensic_record.call_args.kwargs
        assert create["resource_type"] == ResourceType.INSTANCE
