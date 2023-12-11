# Copyright (c) 2022 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
name: route53_unescape
description: Reverse octal escaping in Route53 resource names
short_description: Reverse octal escaping in Route53 resource names
version_added: "1.1.0"
author:
  - Paul Arthur (@flowerysong)
options:
  _input:
    description: A name returned by the AWS Route53 API.
    type: string
    required: true
'''

import re

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.collections import is_string


def octal_replace(x):
    c = int(x.group(1), 8)
    # Only unescape printable ASCII characters that the API will accept
    # unencoded.
    if (c > 0x20 and c < 0x7f):
        return chr(c)

    return x.group(0)


def route53_unescape(value):
    if not is_string(value):
        raise AnsibleFilterError('Invalid value type (%s) for route53_unescape (%r)' % (type(value), value))

    return re.sub(r'\\(\d{3})', octal_replace, value)


class FilterModule:
    def filters(self):
        return {
            'route53_unescape': route53_unescape,
        }
