#!/usr/bin/python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.log import get_logger

logger = get_logger(__name__)


def lambda_handler(event, context):
    """
    response to image builder completion event
    """
    logger.info("image builder completed")
    logger.info(event)
    logger.info(context)
    logger.info(event.get("Records")[0].get("Sns").get("Message"))

    message_body = event.get("Records")[0].get("Sns").get("Message")
    json_body = json.loads(message_body)
    logger.info(json_body["outputResources"]["amis"][0]["image"])
    ami = json_body["outputResources"]["amis"][0]["image"]
    logger.info(f"ami {ami}")
    ssm_key = os.environ["IMAGE_SSM_NAME"]
    logger.info(f"updating ssm {ssm_key}")
    ssm_client = create_aws_client("ssm")
    try:
        result = ssm_client.put_parameter(
            Name=ssm_key,
            Value=ami,
            Type="String",
            DataType="text",
            Tier="Advanced",
            Overwrite=True,
        )
        logger.info(result)
    except Exception as e:
        logger.error(e)

    return create_response(200, {})
