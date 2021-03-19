# (c) 2021 Paul Arthur MacIain
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: hashi_vault
    author: Paul Arthur (@flowerysong)
    short_description: Simple lookup for HashiCorp Vault
    description:
        - Implementation from scratch of a reasonable Ansible lookup for HashiCorp Vault.
        - The community-maintained lookup has accidentally broken its interface multiple times, and retains a number of very crufty interface decisions.
    options:
      _terms:
        description: Paths to look up.
        required: True
      raw:
        description: Controls whether the entire API response is returned, or just the data.
        type: bool
        default: false
      timeout:
        description: The timeout for requests sent to Vault
        type: int
        ini:
          - section: hashi_vault
            key: timeout
      token:
        description: Vault authentication token
        ini:
          - section: hashi_vault
            key: token
      url:
        description: Vault URL
        ini:
          - section: hashi_vault
            key: url
      verify:
        description: Controls whether the TLS certificate for the connection is verified.
        type: bool
        default: true
        ini:
          - section: hashi_vault
            key: verify
    notes:
      - Your definition of reasonable may vary.
"""

EXAMPLES = """
- name: Look up a standard secret
  debug:
   msg: The result is: {{ lookup('flowerysong.melange.hashi_vault', 'secret/ping') }}

- name: Look up multiple secrets
  debug:
    msg: The results are: {{ query('flowerysong.melange.hashi_vault', 'secret/ping', 'secret/penguin') }}

- name: Look up a K/V v2 secret's data
  debug:
    msg: The result is: {{ lookup('flowerysong.melange.hashi_vault', 'secret/data/ping').data }}

- name: Get the entire raw response
  debug:
    msg: The result is: {{ lookup('flowerysong.melange.hashi_vault', 'secret/config', raw=true) }}

- name: Use a variable to configure the lookup
  debug:
    msg: The result is: {{ lookup('flowerysong.melange.hashi_vault', 'secret/ping', **hashi_conf)
  vars:
    hashi_conf:
      token: s.b5lmbxyphjvhcfesmdffqhun
      raw: true
"""

RETURN = """
  _raw:
    description:
      - Secrets
    type: list
    elements: dict
"""

from ansible.errors import AnsibleError
from ansible.module_utils.basic import missing_required_lib
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

HAS_HVAC = False
hvac_importerror = None
try:
    import hvac
    from requests.exceptions import RequestException
    HAS_HVAC = True
except ImportError as e:
    hvac_importerror = e


display = Display()


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not HAS_HVAC:
            raise AnsibleError(missing_required_lib('hvac'), orig_exc=hvac_importerror)

        self.set_options(direct=kwargs)

        ret = []

        client_kwargs = {
            'verify': self.get_option('verify'),
        }
        for opt in ('timeout', 'token', 'url'):
            if self.get_option(opt):
                client_kwargs[opt] = self.get_option(opt)

        client = hvac.Client(**client_kwargs)

        for term in terms:
            display.debug('hashi_vault lookup term: {}'.format(term))

            try:
                secret = client.read(term)
            except (hvac.exceptions.VaultError, RequestException) as e:
                raise AnsibleError('Unable to fetch secret', orig_exc=e)

            display.vvvv('hashi_vault lookup found {}'.format(secret))

            if secret:
                if not self.get_option('raw'):
                    secret = secret['data']
                ret.append(secret)
            else:
                raise AnsibleError('Unable to find secret matching "{}"'.format(term))

        return ret
