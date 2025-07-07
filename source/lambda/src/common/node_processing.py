from aws_xray_sdk.core import xray_recorder

from ..common.log import get_logger

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("normalize_instance_ids")
def normalize_instance_ids(instance_input):
    """
    Normalize instance ID input to always return a list of instance IDs.

    Args:
        instance_input: Can be a string (single instance ID) or a list of instance IDs

    Returns:
        list: A list of instance IDs

    Examples:
        >>> normalize_instance_ids("i-1234567890")
        ['i-1234567890']
        >>> normalize_instance_ids(["i-1234567890", "i-0987654321"])
        ['i-1234567890', 'i-0987654321']
        >>> normalize_instance_ids(None)
        []
    """
    if not instance_input:
        return []
    if isinstance(instance_input, str):
        return [instance_input]
    if isinstance(instance_input, list):
        return instance_input
    # If it's any other type, try to convert to string and return as single-item list
    try:
        return [str(instance_input)]
    except Exception as e:
        logger.error(
            f"Error Node processing for instance {instance_input}: {str(e)}"
        )
        return []


@xray_recorder.capture("normalize_instance_info")
def normalize_instance_info(instance_info_input):
    """
    Normalize instance info input to always return a dictionary with instance IDs as keys.

    Args:
        instance_info_input: Can be a dictionary or a list of dictionaries

    Returns:
        dict: A dictionary with instance IDs as keys and their info as values

    Examples:
        >>> normalize_instance_info({"InstanceId": "i-1234", "PlatformName": "Linux"})
        {'i-1234': {'PlatformName': 'Linux', 'InstanceId': 'i-1234'}}
        >>> normalize_instance_info([
        ...     {"InstanceId": "i-1234", "PlatformName": "Linux"},
        ...     {"InstanceId": "i-5678", "PlatformName": "Windows"}
        ... ])
        {
            'i-1234': {'PlatformName': 'Linux', 'InstanceId': 'i-1234'},
            'i-5678': {'PlatformName': 'Windows', 'InstanceId': 'i-5678'}
        }
    """
    normalized_info = {}

    if not instance_info_input:
        return normalized_info

    # If it's already a dictionary
    if isinstance(instance_info_input, dict):
        # Check if it's a single instance info dictionary
        if "InstanceId" in instance_info_input:
            instance_id = instance_info_input["InstanceId"]
            normalized_info[instance_id] = instance_info_input
        else:
            # It's already in the desired format with instance IDs as keys
            normalized_info = instance_info_input

    # If it's a list of dictionaries
    elif isinstance(instance_info_input, list):
        for instance in instance_info_input:
            if isinstance(instance, dict) and "InstanceId" in instance:
                instance_id = instance["InstanceId"]
                normalized_info[instance_id] = instance

    return normalized_info
