# Copyright (c) 2024 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
name: to_uuid
short_description: Convert a binary UUID to the string representation
version_added: "1.1.0"
author:
  - Paul Arthur (@flowerysong)
options:
  _input:
    description: A base64 encoded binary value
    type: string
    required: true
'''

from base64 import b64decode
from uuid import UUID

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.collections import is_string


def convert_to_uuid(value):
    if not is_string(value):
        raise AnsibleFilterError(f'Invalid value type ({type(value)}) for to_uuid ({repr(value)})')

    try:
        uuid_bytes = b64decode(value)
    except ValueError as e:
        raise AnsibleFilterError(f'Unable to decode "{value}" as base64 in to_uuid: {e}')

    try:
        uuid = UUID(bytes=uuid_bytes)
    except ValueError as e:
        raise AnsibleFilterError(f'Invalid value ({value}) for to_uuid: {e}')

    return str(uuid)


class FilterModule:
    def filters(self):
        return {
            'to_uuid': convert_to_uuid,
        }
