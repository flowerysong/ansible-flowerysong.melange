#!/usr/bin/python

# Copyright (c) 2019 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
module: aws_data_lifecycle_manager
short_description: Manage AWS Data Lifecycle Manager policies
description:
  - Manage AWS Data Lifecycle Manager policies.
version_added: "2.10"
options:
  copy_tags:
    type: bool
    default: false
  description: {}
  enabled:
    type: bool
    default: true
  exclude_boot_volume:
    type: bool
    default: false
  interval:
    type: int
    default: 24
  policy_id: {}
  resource_type:
    choices:
      - instance
      - volume
    default: volume
  retain:
    type: int
    default: 7
  role: {}
  schedule_name:
    default: Default Schedule
  start_time:
    default: 00:00
  state:
    choices:
      - present
      - absent
    default: present
  tags_to_add:
    type: dict
    default: {}
  target_tags:
    type: dict
  variable_tags:
    type: dict
    default: {}

extends_documentation_fragment:
  - amazon.aws.aws
  - amazon.aws.ec2
'''

EXAMPLES = '''
'''

RETURN = '''
'''

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.amazon.aws.plugins.module_utils.core import (
    AnsibleAWSModule,
    is_boto3_error_code,
)
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import (
    ansible_dict_to_boto3_tag_list,
    boto3_tag_list_to_ansible_dict,
)

try:
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    pass  # Handled by AnsibleAWSModule


def process_target_tags(target_tags):
    # We can't use ansible_dict_to_boto3_tag_list because we need to support
    # multiple values for the same tag name.
    result = []
    for (tag, value) in target_tags.items():
        if isinstance(value, list):
            for val in value:
                result.append({
                    'Key': tag,
                    'Value': to_native(val),
                })
        else:
            result.append({
                'Key': tag,
                'Value': to_native(value),
            })
    return result


def find_existing_policy(module, client):
    if module.params['policy_id']:
        try:
            response = client.get_lifecycle_policy(PolicyId=module.params['policy_id'])
        except is_boto3_error_code('ResourceNotFoundException'):
            return None
        except (BotoCoreError, ClientError) as e:
            module.fail_json_aws(e, msg='Failed to fetch existing policy.')

        return response['Policy']

    query_tags = []
    for tag in process_target_tags(module.params['target_tags']):
        query_tags.append('{Key}={Value}'.format(**tag))

    try:
        response = client.get_lifecycle_policies(
            ResourceTypes=[module.params['resource_type'].upper()],
            TargetTags=query_tags,
        )
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg='Failed to fetch existing policies.')

    for policy in response['Policies']:
        try:
            response = client.get_lifecycle_policy(PolicyId=policy['PolicyId'])
        except is_boto3_error_code('ResourceNotFoundException'):
            continue
        except (BotoCoreError, ClientError) as e:
            module.fail_json_aws(e, msg='Failed to fetch existing policy.')

        # If it has more tags than we requested it's not a match
        if len(response['Policy']['PolicyDetails']['TargetTags']) == len(query_tags):
            return response['Policy']

    return None


def build_policy(module):
    policy = {
        'ExecutionRoleArn': module.params['role'],
        'State': 'ENABLED' if module.params['enabled'] else 'DISABLED',
        'Description': module.params['description'],
    }

    details = {
        # This is currently the only valid value
        'PolicyType': 'EBS_SNAPSHOT_MANAGEMENT',
        # This takes a list, but the list can currently only contain one item
        'ResourceTypes': [module.params['resource_type'].upper()],
        'TargetTags': process_target_tags(module.params['target_tags']),
    }

    # Another single-element list
    details['Schedules'] = [{
        # The API docs claim Name is optional, but the API says it is required.
        'Name': module.params['schedule_name'],
        'CreateRule': {
            'Interval': module.params['interval'],
            'IntervalUnit': 'HOURS',
            'Times': [module.params['start_time']],
        },
        'RetainRule': {
            'Count': module.params['retain'],
        },
        'CopyTags': module.params['copy_tags'],
        'TagsToAdd': ansible_dict_to_boto3_tag_list(module.params['tags_to_add']),
    }]

    if module.params['resource_type'] == 'instance':
        details['Parameters'] = {
            'ExcludeBootVolume': module.params['exclude_boot_volume'],
        }
        details['Schedules'][0]['VariableTags'] = ansible_dict_to_boto3_tag_list(module.params['variable_tags'])

    policy['PolicyDetails'] = details
    return policy


def main():
    argument_spec = dict(
        role=dict(),
        policy_id=dict(),
        description=dict(),
        schedule_name=dict(default='Default Schedule'),
        state=dict(choices=['present', 'absent'], default='present'),
        enabled=dict(type='bool', default=True),
        resource_type=dict(choices=['instance', 'volume'], default='volume'),
        exclude_boot_volume=dict(type='bool', default=False),
        target_tags=dict(type='dict'),
        start_time=dict(default='00:00'),
        interval=dict(type='int', default=24),
        retain=dict(type='int', default=7),
        copy_tags=dict(type='bool', default=False),
        tags_to_add=dict(type='dict', default={}),
        variable_tags=dict(type='dict', default={}),
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[['policy_id', 'target_tags']],
        required_if=[['state', 'present', ['description', 'role', 'target_tags']]],
    )

    client = module.client('dlm')

    existing_policy = find_existing_policy(module, client)

    if module.params['state'] == 'absent':
        if not existing_policy:
            module.exit_json(changed=False)

        if not module.check_mode:
            try:
                client.delete_lifecycle_policy(
                    PolicyId=existing_policy['PolicyId'],
                )
            except is_boto3_error_code('ResourceNotFoundException'):
                pass
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg='Failed to delete policy.')

        module.exit_json(changed=True)

    changed = False
    new_policy = build_policy(module)

    if existing_policy:
        existing_policy.pop('DateCreated')
        existing_policy.pop('DateModified')
        new_policy['PolicyId'] = existing_policy['PolicyId']

        if existing_policy != new_policy:
            changed = True
            if not module.check_mode:
                try:
                    result = client.update_lifecycle_policy(**new_policy)
                except (BotoCoreError, ClientError) as e:
                    module.fail_json_aws(e, msg='Failed to modify policy.')
    else:
        if module.params['policy_id']:
            module.fail_json(msg='Could not find a policy with the ID {0}.'.format(module.params['policy_id']))

        changed = True
        if not module.check_mode:
            try:
                result = client.create_lifecycle_policy(**new_policy)
            except (BotoCoreError, ClientError) as e:
                module.fail_json_aws(e, msg='Failed to create policy.')
            new_policy.update(result)

    policy = camel_dict_to_snake_dict(new_policy, ignore_list=['TagsToAdd', 'VariableTags'])
    for key in ['tags_to_add', 'variable_tags']:
        if key in policy['policy_details']['schedules'][0]:
            policy['policy_details']['schedules'][0][key] = boto3_tag_list_to_ansible_dict(policy['policy_details']['schedules'][0][key])

    module.exit_json(changed=changed, policy=policy)


if __name__ == '__main__':
    main()
