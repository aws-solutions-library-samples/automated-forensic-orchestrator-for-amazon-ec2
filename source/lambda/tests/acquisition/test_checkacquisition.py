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

import pytest

from ...src.acquisition.checkacquisition import (
    lambda_handler as function_under_test,
)


@pytest.fixture(scope="function", autouse=True)
def setup_event(request):
    print("Testing Check Acquisition Started")

    def teardown():
        print("Testing Check Acquisition Completed")

    request.addfinalizer(teardown)


def test_check_acquisition_with_cluster_info_all_required():
    """Test acquisition check when all instances require acquisition"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {
                    "affectedNode": [
                        "i-1234567890abcdef0",
                        "i-0987654321fedcba0",
                        "i-1111222233334444",
                    ]
                },
                "isAcquisitionRequired": {
                    "i-1234567890abcdef0": True,
                    "i-0987654321fedcba0": True,
                    "i-1111222233334444": True,
                },
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is True
    assert set(body.get("clusterInfo").get("affectedNode")) == {
        "i-1234567890abcdef0",
        "i-0987654321fedcba0",
        "i-1111222233334444",
    }
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_with_cluster_info_partial_required():
    """Test acquisition check when only some instances require acquisition"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {
                    "affectedNode": [
                        "i-1234567890abcdef0",
                        "i-0987654321fedcba0",
                        "i-1111222233334444",
                    ]
                },
                "isAcquisitionRequired": {
                    "i-1234567890abcdef0": True,
                    "i-0987654321fedcba0": False,
                    "i-1111222233334444": True,
                },
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is True
    assert set(body.get("clusterInfo").get("affectedNode")) == {
        "i-1234567890abcdef0",
        "i-1111222233334444",
    }
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_with_cluster_info_none_required():
    """Test acquisition check when no instances require acquisition"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {
                    "affectedNode": [
                        "i-1234567890abcdef0",
                        "i-0987654321fedcba0",
                        "i-1111222233334444",
                    ]
                },
                "isAcquisitionRequired": {
                    "i-1234567890abcdef0": False,
                    "i-0987654321fedcba0": False,
                    "i-1111222233334444": False,
                },
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is False
    # Original affectedNode list is preserved when no instances require acquisition
    assert body.get("clusterInfo").get("affectedNode") == [
        "i-1234567890abcdef0",
        "i-0987654321fedcba0",
        "i-1111222233334444",
    ]
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_with_cluster_info_missing_instances():
    """Test acquisition check when some instances are missing from acquisition dict"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {
                    "affectedNode": [
                        "i-1234567890abcdef0",
                        "i-0987654321fedcba0",
                        "i-1111222233334444",
                    ]
                },
                "isAcquisitionRequired": {
                    "i-1234567890abcdef0": True,
                    "i-0987654321fedcba0": False,
                    # i-1111222233334444 is missing
                },
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is True
    assert body.get("clusterInfo").get("affectedNode") == [
        "i-1234567890abcdef0"
    ]
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_without_cluster_info():
    """Test acquisition check when clusterInfo is not present"""
    event = {
        "Payload": {
            "body": {
                "forensicId": "test-forensic-id",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-east-1",
                "someOtherData": "test-data",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("forensicId") == "test-forensic-id"
    assert body.get("instanceAccount") == "123456789012"
    assert body.get("instanceRegion") == "us-east-1"
    assert body.get("someOtherData") == "test-data"
    # Should not have isAcquisitionRequired or clusterInfo modifications


def test_check_acquisition_empty_affected_nodes():
    """Test acquisition check with empty affected nodes list"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {"affectedNode": []},
                "isAcquisitionRequired": {},
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is False
    # Original empty list is preserved
    assert body.get("clusterInfo").get("affectedNode") == []
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_single_instance_required():
    """Test acquisition check with single instance requiring acquisition"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {"affectedNode": ["i-1234567890abcdef0"]},
                "isAcquisitionRequired": {"i-1234567890abcdef0": True},
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is True
    assert body.get("clusterInfo").get("affectedNode") == [
        "i-1234567890abcdef0"
    ]
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_single_instance_not_required():
    """Test acquisition check with single instance not requiring acquisition"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {"affectedNode": ["i-1234567890abcdef0"]},
                "isAcquisitionRequired": {"i-1234567890abcdef0": False},
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is False
    # Original affectedNode list is preserved when no instances require acquisition
    assert body.get("clusterInfo").get("affectedNode") == [
        "i-1234567890abcdef0"
    ]
    assert body.get("forensicId") == "test-forensic-id"


def test_check_acquisition_preserves_additional_cluster_info():
    """Test that additional cluster info is preserved"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {
                    "affectedNode": ["i-1234567890abcdef0"],
                    "clusterName": "test-cluster",
                    "namespace": "default",
                    "region": "us-east-1",
                },
                "isAcquisitionRequired": {"i-1234567890abcdef0": True},
                "forensicId": "test-forensic-id",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is True
    cluster_info = body.get("clusterInfo")
    assert cluster_info.get("affectedNode") == ["i-1234567890abcdef0"]
    assert cluster_info.get("clusterName") == "test-cluster"
    assert cluster_info.get("namespace") == "default"
    assert cluster_info.get("region") == "us-east-1"


def test_check_acquisition_complex_scenario():
    """Test complex scenario with mixed acquisition requirements"""
    event = {
        "Payload": {
            "body": {
                "clusterInfo": {
                    "affectedNode": [
                        "i-1234567890abcdef0",
                        "i-0987654321fedcba0",
                        "i-1111222233334444",
                        "i-5555666677778888",
                        "i-9999aaaabbbbcccc",
                    ],
                    "clusterName": "production-cluster",
                    "namespace": "kube-system",
                },
                "isAcquisitionRequired": {
                    "i-1234567890abcdef0": True,
                    "i-0987654321fedcba0": False,
                    "i-1111222233334444": True,
                    "i-5555666677778888": False,
                    "i-9999aaaabbbbcccc": True,
                },
                "forensicId": "complex-forensic-id",
                "instanceAccount": "123456789012",
                "instanceRegion": "us-west-2",
            }
        }
    }

    result = function_under_test(event, "")

    assert result.get("statusCode") == 200
    body = result.get("body")
    assert body.get("isAcquisitionRequired") is True

    expected_instances = {
        "i-1234567890abcdef0",
        "i-1111222233334444",
        "i-9999aaaabbbbcccc",
    }
    actual_instances = set(body.get("clusterInfo").get("affectedNode"))
    assert actual_instances == expected_instances

    # Verify other data is preserved
    assert body.get("forensicId") == "complex-forensic-id"
    assert body.get("instanceAccount") == "123456789012"
    assert body.get("instanceRegion") == "us-west-2"
    assert body.get("clusterInfo").get("clusterName") == "production-cluster"
    assert body.get("clusterInfo").get("namespace") == "kube-system"
