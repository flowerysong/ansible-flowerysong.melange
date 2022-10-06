# Copyright (c) 2022 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
name: sts_allow
short_description: Produce an sts:AssumeRole statement for a principal
version_added: "1.1.0"
author:
  - Paul Arthur (@flowerysong)
options:
  _input:
    description: A principal type and value
    type: list
    required: true
'''

def sts_allow(value):
    princ = value[1]
    if value[0] == 'AWS':
        princ = f'arn:aws:iam::{value[1]}:root'
    return {
        'Effect': 'Allow',
        'Action': 'sts:AssumeRole',
        'Principal': {
            value[0]: princ,
        },
    }


class FilterModule:
    def filters(self):
        return {
            'sts_allow': sts_allow,
        }
