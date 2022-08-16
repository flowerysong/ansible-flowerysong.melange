#!/usr/bin/python
# Copyright (c) 2022 Paul Arthur MacIain
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: ec2_eip_attribute_info
version_added: 1.1.0
short_description: Retrieve attributes of AWS EC2 Elastic IPs
description:
  - Retrieve attributes of AWS EC2 Elastic IPs.
author:
  - Paul Arthur (@flowerysong)
options:
  allocation_ids:
    description:
      - EIPs to retrieve attributes for.
    required: true
    type: list
    elements: str
    aliases:
     - allocation_id
extends_documentation_fragment:
- amazon.aws.aws
- amazon.aws.ec2

'''

EXAMPLES = r'''
'''


RETURN = '''
'''

try:
    from botocore.exceptions import (BotoCoreError, ClientError)
except ImportError:
    pass  # caught by imported AnsibleAWSModule

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict

from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import AWSRetry


def main():
    module = AnsibleAWSModule(
        argument_spec=dict(
            allocation_ids=dict(
                type='list',
                elements='str',
                required=True,
                aliases=['allocation_id'],
            ),
        ),
        supports_check_mode=True,
    )

    client = module.client('ec2', retry_decorator=AWSRetry.jittered_backoff())
    try:
        response = client.describe_addresses_attribute(
            AllocationIds=module.params['allocation_ids'],
            Attribute='domain-name',
            aws_retry=True,
        )
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg='Failed to fetch address attributes')

    addresses = camel_dict_to_snake_dict(response)['addresses']
    module.exit_json(changed=False, addresses=addresses)


if __name__ == '__main__':
    main()
