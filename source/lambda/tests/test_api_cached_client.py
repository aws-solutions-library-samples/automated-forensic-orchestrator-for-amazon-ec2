#!/usr/bin/python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# Note: tests are executed in the build process from the assembled code in
# /deployment/temp
#

from ..src.common.awsapi_cached_client import AWSCachedClient
import pytest


@pytest.mark.skip(reason="Not working due to local credential")
def test_create_client():
    AWS = AWSCachedClient("us-east-1")

    AWS.get_connection("sns")  # in us-east-1
    my_account = AWS.account
    assert my_account
    assert "sns" in AWS.client
    assert "us-east-1" in AWS.client["sns"]
    AWS.get_connection("ec2")
    assert "ec2" in AWS.client
    assert "us-east-1" in AWS.client["ec2"]
    AWS.get_connection("iam", "ap-northeast-1")
    assert "iam" in AWS.client
    assert "ap-northeast-1" in AWS.client["iam"]
