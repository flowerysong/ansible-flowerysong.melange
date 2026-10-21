# Copyright (c) 2026 Paul Arthur
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
name: acme_authz
description: Collate DNS challenge records for ACME
short_description: Collate DNS challenge records for ACME
version_added: "1.2.0"
author:
  - Paul Arthur (@flowerysong)
options:
  _input:
    description: ACME challenge data
    type: dict
    required: true
  domain_map:
    description: Map of domains to canonical locations
    type: dict
    required: false
'''


def acme_authz(value, domain_map):
    res = {}
    for k, v in value.items():
        dom = '.'.join([v['dns-01']['resource'], domain_map.get(k, k)])
        res.setdefault(dom, []).append(''.join(['"', v['dns-01']['resource_value'], '"']))
    return res


class FilterModule:
    def filters(self):
        return {
            'acme_authz': acme_authz,
        }
