#!/usr/bin/python

# Copyright (c) 2019 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: aws_data_lifecycle_manager
short_description: Manage AWS Data Lifecycle Manager policies
description:
  - Manage AWS Data Lifecycle Manager policies.
version_added: "1.0.0"
author:
  - Paul Arthur (@flowerysong)
options:
  copy_tags:
    description:
      - Copy tags from the source volume to the snapshot.
    type: bool
    default: false
  description:
    description:
      - A description of the policy.
      - Required if I(state=present).
    type: str
  enabled:
    description:
      - Enable or disable the policy.
    type: bool
    default: true
  exclude_boot_volume:
    description:
      - Exclude the boot volume from snapshots.
      - Only valid when I(resource_type=instance).
    type: bool
    default: false
  interval:
    description:
      - The interval between snapshots, in hours.
    type: int
    choices:
      - 1
      - 2
      - 3
      - 4
      - 6
      - 8
      - 12
      - 24
    default: 24
  policy_id:
    description:
      - ID of an existing policy.
      - Required if I(state=absent) and I(target_tags) is not set.
    type: str
  resource_type:
    description:
      - Target resource type for the policy.
    type: str
    choices:
      - instance
      - volume
    default: volume
  retain:
    description:
      - The number of snapshots to retain for each volume.
    type: int
    default: 7
  role:
    description:
      - The ARN of the role used to execute actions specified by the policy.
      - Required if I(state=present).
    type: str
  schedule_name:
    description:
      - The name of the schedule.
    type: str
    default: Default Schedule
  start_time:
    description:
      - The base time (in UTC) for operations.
      - The operation will trigger within a one-hour window following the specified time.
    type: str
    default: 00:00
  state:
    description:
      - Create or delete the policy.
    type: str
    choices:
      - present
      - absent
    default: present
  tags_to_add:
    description:
      - Extra tags to add to resources created by the policy.
    type: dict
    default: {}
  target_tags:
    description:
      - Tags that identify the resources targeted by the policy.
      - Required if I(state=present) or if I(policy_id) is not set.
    type: dict
  variable_tags:
    description:
      - Special templated tags to add to resources created by the policy.
      - Only valid when I(resource_type=instance).
      - Tag names follow normal AWS rules, values can be C($(instance-id)) or C($(timestamp))
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
        except (BotoCoreError, ClientError) as e:   # pylint: disable=duplicate-except
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
        except (BotoCoreError, ClientError) as e:   # pylint: disable=duplicate-except
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
        interval=dict(type='int', choices=[1, 2, 3, 4, 6, 8, 12, 24], default=24),
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
            except (BotoCoreError, ClientError) as e:   # pylint: disable=duplicate-except
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
