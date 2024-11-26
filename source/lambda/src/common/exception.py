#!/usr/bin/python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json


class ForensicLambdaExecutionException(Exception):
    """Forensic Lambda Execution Exception"""

    pass


class ForensicExecutionException(Exception):
    def __init__(self, error_content: dict) -> None:
        error_content_str = json.dumps(error_content)
        super().__init__(error_content_str)


class MemoryAcquisitionError(ForensicExecutionException):
    """Forensic Lambda Execution Exception Memory Acquisition failed"""

    pass


class DiskAcquisitionError(ForensicExecutionException):
    """Forensic Lambda Execution Exception Disk Acquisition failed"""

    pass


class InvestigationError(ForensicExecutionException):
    """Forensic Lambda Execution Exception Disk Acquisition failed"""

    pass
