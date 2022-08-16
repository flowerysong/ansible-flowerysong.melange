#!/usr/bin/python

# Copyright (c) 2022 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: ec2_eip_attribute
short_description: Manage attributes of AWS EC2 Elastic IPs
description:
  - Manage attributes of AWS EC2 Elastic IPs.
version_added: "1.1.0"
author:
  - Paul Arthur (@flowerysong)
options:
  allocation_id:
    description:
      - ID of the EIP to manage
    type: str
  domain_name:
    description:
      - rDNS domain name.
    type: str
    required: false
extends_documentation_fragment:
  - amazon.aws.aws
  - amazon.aws.ec2
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict

from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import AWSRetry

try:
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    pass  # Handled by AnsibleAWSModule


def main():
    argument_spec = dict(
        allocation_id=dict(),
        domain_name=dict(required=False),
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    domain_name = module.params['domain_name']
    client = module.client('ec2', retry_decorator=AWSRetry.jittered_backoff())
    allocation_id = module.params['allocation_id']

    try:
        response = client.describe_addresses_attribute(
            AllocationIds=[allocation_id],
            Attribute='domain-name',
            aws_retry=True,
        )
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg='Failed to fetch address attributes')

    address = {}
    # Find the most recently set value, even if it's pending
    if len(response['Addresses']) == 0:
        current_ptr = None

    elif len(response['Addresses']) == 1:
        address = response['Addresses'][0]
        if response['Addresses'][0].get('PtrRecordUpdate', {}).get('Status') == 'PENDING':
            current_ptr = response['Addresses'][0]['PtrRecordUpdate']['Value']
        else:
            current_ptr = response['Addresses'][0]['PtrRecord']

    else:
        module.fail_json(
            msg='Unexpected number of results when describing address attributes for {0}'.format(allocation_id),
            response=response,
        )

    changed = False

    # Make sure both PTR values are canonical
    if domain_name and not domain_name.endswith('.'):
        # Users shouldn't have to remember to do this
        domain_name += '.'
    if current_ptr and not current_ptr.endswith('.'):
        # API weirdness: As of 2022-08-16, after a reset
        # `describe_addresses_attribute()` returns the pending AWS-owned PTR
        # without the trailing `.`, even though the response from
        # `reset_address_attribute()` includes it, as do responses from
        # `describe_addresses_attribute()` for custom PTRs.
        current_ptr += '.'

    if not domain_name:
        if current_ptr and not (current_ptr.endswith('compute.amazonaws.com.')):
            changed = True
            if not module.check_mode:
                try:
                    response = client.reset_address_attribute(
                        AllocationId=allocation_id,
                        Attribute='domain-name',
                        aws_retry=True,
                    )
                except (BotoCoreError, ClientError) as e:
                    module.fail_json_aws(e, msg='Failed to reset address attributes')
                address = response['Address']

    elif current_ptr != domain_name:
        changed = True
        if not module.check_mode:
            try:
                response = client.modify_address_attribute(
                    AllocationId=allocation_id,
                    DomainName=domain_name,
                    aws_retry=True,
                )
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg='Failed to modify address attributes')
            address = response['Address']

    address = camel_dict_to_snake_dict(address)
    module.exit_json(changed=changed, address=address)


if __name__ == '__main__':
    main()
