#!/usr/bin/python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import logging

from aws_xray_sdk.core import patch_all, xray_recorder

patch_all()
xray_recorder.configure(context_missing="LOG_ERROR")


@xray_recorder.capture("Forensic Logger")
def get_logger(name=__name__):
    """
    this is the warper to return a logger with the solution wide configration
    """
    if len(logging.getLogger().handlers) > 0:
        # for deployed env
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.basicConfig(
            format="%(asctime)s %(message)s",
            datefmt="%m/%d/%Y %I:%M:%S %p",
            level=logging.INFO,
        )
    logger = logging.getLogger(name)
    return logger
