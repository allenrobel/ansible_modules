#!/usr/bin/python

# Copyright: (c) 2023, Allen Robel <arobel@me.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from os.path import isfile

DOCUMENTATION = r'''
---
module: create_file

short_description: Create a file

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: If filename does not exist, create it, else do nothing.

options:
    name:
        description: The absolute path to the file. E.g. /tmp/foo
        required: true
        type: str

# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - arobel.tests.create_file

author:
    - Allen Robel (@allenrobel)
'''

EXAMPLES = r'''
# Pass in a message
- name: Create a file
  arobel.tests.create_file:
    name: /tmp/foo
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: '/tmp/foo'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: '/tmp/foo'
'''

from ansible.module_utils.basic import AnsibleModule


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        name=dict(type='str', required=True),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['original_message'] = module.params['name']
    if isfile(module.params['name']):
        result['change'] = False
        result['message'] = f"{module.params['name']} already exists."
        module.exit_json(**result)
    else:
        try:
            open(module.params['name'], 'w').close()
            result['change'] = True
            result['message'] = f"{module.params['name']} created."
            module.exit_json(**result)
        except Exception as e:
            result['change'] = False
            result['message'] = f"Error creating {module.params['name']}.  Exception detail: {e}."
            module.fail_json(msg='Failed to create file.', **result)

def main():
    run_module()


if __name__ == '__main__':
    main()
