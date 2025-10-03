#!/usr/bin/env python3
# pylint: disable=line-too-long, broad-exception-caught

""" handler.py (AWS LAMBDA)
Source: https://github.com/plus3it/terraform-aws-tardigrade-security-controls-remediation

Initiated By: CloudWatch SecurityHub Events Trigger this Lambda, auto remediation of security findings

Remediations:
  - EC2.19: Security groups should not allow unrestricted access to ports with high risk
            https://docs.aws.amazon.com/console/securityhub/EC2.19/remediation

"""

import os
import json
import logging
from typing import Dict, Any, List, Tuple, Callable
import functools
import boto3


#########################################
#              CONSTANTS               #
#########################################
TRUTHY_TAG_VALUES = ['true', 'yes', '1']
REMEDIATION_DESCRIPTION = 'Modified by Security Hub Lambda Remediation'

# EC2.19
EC2_19_OFFENDING_CIDRS = ['0.0.0.0/0', '::/0']


#########################################
#        ENVIRONMENT VARIABLES         #
#########################################
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
DRY_RUN_ENABLED = os.environ.get('DRY_RUN', 'false').lower() in TRUTHY_TAG_VALUES

# EC2.19
EC2_19_EXCEPTION_TAG_KEY = os.environ.get('EC2_19_EXCEPTION_TAG')
EC2_19_REMEDIATION_ACTION = os.environ.get('EC2_19_REMEDIATION_ACTION')
EC2_19_REPLACEMENT_CIDRS = [
    c.strip() for c in os.environ.get('EC2_19_REPLACEMENT_CIDRS', '').split(',')
    if c.strip()
]


#########################################
#            INITIAL SETUP             #
#########################################
logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_CLIENT = boto3.client('sns')  # SNS is region-agnostic for publishing


#########################################
#           DECORATOR FUNCTION          #
#########################################
def dry_run_wrapper(func: Callable) -> Callable:
    """
    Decorator that intercepts a function call if DRY_RUN_ENABLED is True,
    logging the intent instead of executing the function.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        func_name = func.__name__

        positional_args = [repr(a) for a in args[1:]]
        keyword_args = [f"{k}={repr(v)}" for k, v in kwargs.items()]

        all_args = ", ".join(positional_args + keyword_args)

        if DRY_RUN_ENABLED:
            logger.warning("DRY-RUN: Would have called function '%s(%s)'. Execution skipped.", func_name, all_args)
            if func_name in ['ec2_sg_remediate_update', 'ec2_sg_remediate_revoke']:
                return True
            return None

        # If DRY_RUN is False, execute the original function
        return func(*args, **kwargs)

    return wrapper


#########################################
#          HELPER FUNCTIONS            #
#########################################
def get_details_from_finding(event: Dict[str, Any]) -> Tuple[str, str, str] | Tuple[None, None, None]:
    """
    Extracts Control ID, Security Group ID, and Region from the Security Hub finding event.

    Args:
        event: The incoming EventBridge event payload.

    Returns:
        A tuple containing (control_id, sg_id, region) or (None, None, None) on failure.
    """
    try:
        finding = event['detail']['findings'][0]
        control_id = finding['ProductFields']['controlId']
        resource = finding['Resources'][0]
        # Extract SG ID from the resource ARN
        sg_id = resource['Id'].split('/')[-1]
        region = resource['Region']

        return control_id, sg_id, region
    except (KeyError, IndexError):
        logger.error("Event does not contain expected Security Hub finding structure.")
        return None, None, None


def create_ec2_client(region: str) -> boto3.client:
    """Creates a regional EC2 client."""
    return boto3.client('ec2', region_name=region)


def sns_publish_alert(topic_arn: str, subject: str, message: str) -> bool:
    """Publishes a message to the specified SNS topic."""
    try:
        SNS_CLIENT.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        return True
    except Exception as exc:
        logger.error("Error publishing SNS alert: %s", exc)
        return False


def ec2_sg_is_exception_tagged(ec2_client: boto3.client, sg_id: str, tag_name: str) -> bool:
    """
    Checks if the Security Group has the exception tag set to a truthy value.

    Args:
        ec2_client: The regional EC2 client.
        sg_id: The ID of the Security Group.
        tag_name: The AWS Tag to check if ingress rule is allowed

    Returns:
        True if the exception tag is present and truthy, False otherwise.
    """
    try:
        response = ec2_client.describe_tags(
            Filters=[
                {'Name': 'resource-id', 'Values': [sg_id]},
                {'Name': 'key', 'Values': [tag_name]}
            ]
        )
        tags = response.get('Tags', [])

        if not tags:
            return False

        tag_value = tags[0]['Value'].lower()

        if tag_value in TRUTHY_TAG_VALUES:
            # FUTURE CHANGE IDEA: Auto acknowledge Security Hub finding here
            logger.info(
                "SG %s has '%s' set to '%s'. **REMEDIATION EXCEPTION GRANTED.**",
                sg_id, tag_name, tag_value
            )
            return True
        return False

    except Exception as exc:
        logger.error("Error checking tags for SG %s: %s", sg_id, exc)
        return False


def ec2_sg_get_offending_rules(ec2_client: boto3.client, sg_id: str) -> List[Dict[str, Any]]:
    """
    Describes the SG and return a list of matching offending ingress rules (0.0.0.0/0 or ::/0).

    Args:
        ec2_client: The regional EC2 client.
        sg_id: The ID of the Security Group.

    Returns:
        A list of dictionaries, where each dict represents an offending rule.
    """
    offending_rules: List[Dict[str, Any]] = []
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg_details = response['SecurityGroups'][0]

        for rule in sg_details.get('IpPermissions', []):
            # Check IPv4 rules
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') in EC2_19_OFFENDING_CIDRS:
                    offending_rules.append({
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule.get('FromPort'),
                        'ToPort': rule.get('ToPort'),
                        'CidrIp': ip_range['CidrIp']
                    })

            # Check IPv6 rules
            for ipv6_range in rule.get('Ipv6Ranges', []):
                if ipv6_range.get('CidrIpv6') in EC2_19_OFFENDING_CIDRS:
                    offending_rules.append({
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule.get('FromPort'),
                        'ToPort': rule.get('ToPort'),
                        'CidrIpv6': ipv6_range['CidrIpv6']
                    })
    except Exception as exc:
        logger.error("Failed to describe Security Group %s: %s", sg_id, exc)

    return offending_rules


def ec2_sg_revoke_rule(ec2_client: boto3.client, sg_id: str, rule: Dict[str, Any]) -> bool:
    """
    Revokes a specific ingress rule from a security group.

    Args:
        ec2_client: The regional EC2 client.
        sg_id: The ID of the Security Group.
        rule: The specific rule dictionary to revoke.

    Returns:
        True on successful revocation, False otherwise.
    """
    cidr_to_revoke: Dict[str, str] = {}
    if 'CidrIp' in rule:
        cidr_to_revoke = {'CidrIp': rule['CidrIp']}
    elif 'CidrIpv6' in rule:
        cidr_to_revoke = {'CidrIpv6': rule['CidrIpv6']}
    else:
        return False

    revoke_params = {
        'GroupId': sg_id,
        'IpPermissions': [
            {
                'IpProtocol': rule['IpProtocol'],
                'FromPort': rule.get('FromPort'),
                'ToPort': rule.get('ToPort'),
                'IpRanges': [cidr_to_revoke] if 'CidrIp' in cidr_to_revoke else [],
                'Ipv6Ranges': [cidr_to_revoke] if 'CidrIpv6' in cidr_to_revoke else []
            }
        ]
    }
    # Clean up empty lists/dicts before the API call
    if 'IpRanges' in revoke_params['IpPermissions'][0] and not revoke_params['IpPermissions'][0]['IpRanges']:
        del revoke_params['IpPermissions'][0]['IpRanges']
    if 'Ipv6Ranges' in revoke_params['IpPermissions'][0] and not revoke_params['IpPermissions'][0]['Ipv6Ranges']:
        del revoke_params['IpPermissions'][0]['Ipv6Ranges']

    try:
        ec2_client.revoke_security_group_ingress(**revoke_params)
        logger.info("Successfully revoked %s from SG %s.", cidr_to_revoke, sg_id)
        return True
    except Exception as exc:
        logger.error("Error revoking rule for SG %s: %s", sg_id, exc)
        return False


def ec2_sg_authorize_rule(ec2_client: boto3.client, sg_id: str, new_ip_permissions: List[Dict[str, Any]]) -> bool:
    """Authorizes new ingress rules to a security group."""
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=new_ip_permissions
        )
        return True
    except Exception as exc:
        logger.error("Error authorizing new rules for SG %s: %s", sg_id, exc)
        return False


@dry_run_wrapper
def ec2_sg_remediate_update(ec2_client: boto3.client, sg_id: str, rule: Dict[str, Any]) -> str:
    """
    Handles the UPDATE remediation action: replaces an offending rule with approved CIDRs.

    Args:
        ec2_client: The regional EC2 client.
        sg_id: The ID of the Security Group.
        rule: The specific offending rule (already revoked).

    Returns:
        A string summarizing the UPDATE result (SUCCESS or FAILED).
    """
    if not EC2_19_REPLACEMENT_CIDRS:
        error_msg = "UPDATE requested but replacement CIDRs are empty."
        logger.error("SG %s: FAILED to authorize new rules: %s", sg_id, error_msg)
        return f"FAILED: {error_msg}"

    new_ip_permissions: List[Dict[str, Any]] = []
    for cidr in EC2_19_REPLACEMENT_CIDRS:
        permission = {
            'IpProtocol': rule['IpProtocol'],
            'FromPort': rule.get('FromPort'),
            'ToPort': rule.get('ToPort'),
        }
        if ':' in cidr:  # IPv6
            permission['Ipv6Ranges'] = [
                {'CidrIpv6': cidr, 'Description': REMEDIATION_DESCRIPTION}
            ]
        else:  # IPv4
            permission['IpRanges'] = [
                {'CidrIp': cidr, 'Description': REMEDIATION_DESCRIPTION}
            ]
        new_ip_permissions.append(permission)

    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=new_ip_permissions
        )
        return f"SUCCESS: Replaced rule with {len(EC2_19_REPLACEMENT_CIDRS)} CIDRs."
    except Exception as exc:
        error_msg = f"Error authorizing new rules: {exc}"
        logger.error("SG %s: FAILED to authorize new rules: %s", sg_id, error_msg)
        return f"FAILED: {error_msg}"

@dry_run_wrapper
def ec2_sg_remediate_revoke(sg_id: str, rule: Dict[str, Any]) -> str:
    """
    Handles the REVOKE remediation action: sends an SNS alert after revocation.

    Args:
        sg_id: The ID of the Security Group.
        rule: The specific offending rule (already revoked).

    Returns:
        A string summarizing the REVOKE result (SUCCESS or WARNING).
    """
    cidr_value = rule.get('CidrIp') or rule.get('CidrIpv6')
    subject = f"Security Alert: EC2.19 Rule REMOVED from SG {sg_id}"
    message = (
        f"The unrestricted ingress rule ({cidr_value}) on protocol "
        f"{rule['IpProtocol']} in Security Group {sg_id} was automatically REMOVED. "
        "This action was chosen via the 'REVOKE' remediation option."
    )
    try:
        SNS_CLIENT.publish(
            TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message
        )
        return "SUCCESS: Rule deleted and SNS alert sent."
    except Exception as exc:
        # Log a warning, but the rule is technically gone, so it's not a hard FAILED result.
        warning_msg = f"Rule deleted, but failed to send SNS alert: {exc}"
        logger.warning(
            "SG %s: WARNING - %s",
            sg_id, warning_msg
        )
        return f"WARNING: {warning_msg}"


def ec2_sg_handle_remediation(ec2_client: boto3.client, sg_id: str) -> str:
    """
    Handles the EC2.19 remediation flow (validation, skip checks, and dispatch).

    Args:
        ec2_client: The regional EC2 client.
        sg_id: The ID of the Security Group.

    Returns:
        A string summarizing the remediation result.
    """
    if EC2_19_REMEDIATION_ACTION == "SKIP":
        msg = "DISABLED: Remediation skipped by configuration."
        logger.info("SG %s: %s", sg_id, msg)
        return msg

    if ec2_sg_is_exception_tagged(ec2_client, sg_id, EC2_19_EXCEPTION_TAG_KEY):
        msg = f"SKIP: [{sg_id}] Exception tag found"
        logger.info(msg)
        return msg

    offending_rules = ec2_sg_get_offending_rules(ec2_client, sg_id)

    if not offending_rules:
        msg = f"SKIP: [{sg_id}] No offending rules found."
        logger.info(msg)
        return msg

    results: List[str] = []

    for rule in offending_rules:
        if not ec2_sg_revoke_rule(ec2_client, sg_id, rule):
            error_msg = f"Could not revoke rule {rule}"
            logger.error("SG %s: FAILED to revoke offending rule: %s", sg_id, error_msg)
            results.append(f"FAILED: {error_msg}")
            continue

        if EC2_19_REMEDIATION_ACTION == "UPDATE":
            result = ec2_sg_remediate_update(ec2_client, sg_id, rule)
        elif EC2_19_REMEDIATION_ACTION == "REVOKE":
            result = ec2_sg_remediate_revoke(sg_id, rule)
        else:
            result = "ERROR: Unknown action."
            logger.error("SG %s: ERROR - Unknown action requested.", sg_id)

        results.append(result)

    return f"COMPLETED: {'; '.join(results)}"

#########################################
#         INVOKING FUNCTIONS           #
#########################################
def lambda_handler(event, context):  #pylint: disable=unused-argument
    """
    Central dispatcher for Security Hub remediation
    """

    control_id, sg_id, region = get_details_from_finding(event)

    if not control_id or not sg_id or not region:
        return {'statusCode': 400, 'body': 'Could not extract essential finding details.'}

    logger.info("Processing finding %s for SG %s in %s.", control_id, sg_id, region)

    # Initialize the client to the finding's region for multi-region support
    ec2_client = create_ec2_client(region)

    # Check the control ID and dispatch to the handler function
    if control_id == "EC2.19":
        result = ec2_sg_handle_remediation(ec2_client, sg_id)
        logger.info("EC2.19 Remediation Result: %s", result)

        return {'statusCode': 200, 'body': json.dumps({'result': result})}

    # Future remediation handlers would go here:
    # elif control_id == "S3.1":
    #    result = s3_bucket_handle_remediation(s3_client, resource_arn)
    #    logger.info(f"S3.1 Remediation Result: {result}")

    logger.info("Finding %s is not configured for remediation in this Lambda.", control_id)
    return {'statusCode': 200, 'body': 'Finding control ID not handled by this function.'}
