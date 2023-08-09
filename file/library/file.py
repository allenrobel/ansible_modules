#!/usr/bin/python

# Copyright: (c) 2023, Allen Robel <arobel@me.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from os.path import isfile
from os import remove

DOCUMENTATION = r'''
---
module: file

short_description: Create, delete, update files.

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: If filename does not exist, create it, else do nothing.

options:
    name:
        description: The absolute path to the file. E.g. /tmp/foo
        required: true
        type: str
    state:
        description: Either merged or deleted. If merged, the file will be created, if it doesn't exist.  If deleted, the file will be deleted if it does exist.
        required: true
        type: str
    content:
        description: content to add to the file, if state == merged.  If state == deleted, content is ignored.
        required: false
        type: str

# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - arobel.tests.file

author:
    - Allen Robel (@allenrobel)
'''

EXAMPLES = r'''
# Create file /tmp/foo
- name: Create /tmp/foo
  file:
    name: /tmp/foo
    state: merged

# Create file /tmp/foo with content
- name: Create /tmp/foo
  file:
    name: /tmp/foo
    state: merged
    content: |
        The only way to achieve the impossible
        is to believe that it is possible.

# Delete file /tmp/foo
- name: Delete /tmp/foo
  file:
    name: /tmp/foo
    state: deleted
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
filename:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: '/tmp/foo'
state:
    description: One of merged, overidden, deleted 
    type: str
    returned: always
    sample: merged
message:
    description: Output message.
    type: str
    returned: always
    sample: 'File /tmp/foo created.'
'''

from ansible.module_utils.basic import AnsibleModule


def run_module():
    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
        filename='',
        message=''
    )

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        name=dict(type='str', required=True),
        state=dict(type='str', required=True),
        content=dict(type='str', required=False, default="")
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
    def handle_merged_no_content(module):
        if isfile(module.params['name']):
            result['message'] = f"{module.params['name']} already exists."
            module.exit_json(**result)
        try:
            open(module.params['name'], 'w').close()
            result['changed'] = True
            result['message'] = f"{module.params['name']} created."
            module.exit_json(**result)
        except Exception as e:
            result['changed'] = False
            result['failed'] = True
            result['message'] = f"Error creating {module.params['name']}.  Exception detail: {e}."
            module.fail_json(msg='Failed to create file.', **result)

    def content_needs_update(module):
        try:
            with open(module.params['name'], "r") as handle:
                content = handle.read()
        except Exception as e:
            if result['changed'] != True:
                result['changed'] = False
            result['failed'] = True
            result['message'] = f"Error reading from {module.params['name']}.  Exception detail: {e}."
            module.fail_json(msg='Failed to read file.', **result)
        if content == module.params['content']:
            return False
        return True

    def handle_merged_with_content(module):
        if not isfile(module.params['name']):
            try:
                with open(module.params['name'], "w") as handle:
                    handle.write(module.params['content'])
                result['changed'] = True
                result['message'] = f"{module.params['name']} created and updated."
            except Exception as e:
                if result['changed'] != True:
                    result['changed'] = False
                result['failed'] = True
                result['message'] = f"Error creating and writing to {module.params['name']}.  Exception detail: {e}."
                module.fail_json(msg='Failed to create or write file.', **result)

        if not content_needs_update(module):
            result['changed'] = False
            result['message'] = f"Nothing do to. {module.params['name']} content matches."
            module.exit_json(**result)

        try:
            with open(module.params['name'], "w") as handle:
                handle.write(module.params['content'])
            result['changed'] = True
            result['message'] = f"{module.params['name']} content updated."
            module.exit_json(**result)
        except Exception as e:
            if result['changed'] != True:
                result['changed'] = False
            result['failed'] = True
            result['message'] = f"Error updating {module.params['name']} content.  Exception detail: {e}."
            module.fail_json(msg='Failed to write file.', **result)

    def handle_overridden(module):
        if isfile(module.params['name']):
            action_past_tense = "overwritten"
            action_present_tense = "overwritting"
        else:
            action_past_tense = "created and populated"
            action_present_tense = "creating and populating"

        try:
            with open(module.params['name'], "w") as handle:
                handle.write(module.params['content'])
            result['changed'] = True
            result['message'] = f"{module.params['name']} {action_past_tense}."
            module.exit_json(**result)
        except Exception as e:
            if result['changed'] != True:
                result['changed'] = False
            result['failed'] = True
            result['message'] = f"Error {action_present_tense} {module.params['name']}.  Exception detail: {e}."
            module.fail_json(msg='Failed to overwrite.', **result)

    def handle_deleted(module):
        if not isfile(module.params['name']):
            result['changed'] = False
            result['message'] = f"Nothing to do. {module.params['name']} doesn't exist."
            module.exit_json(**result)
        try:
            remove(module.params['name'])
            result['changed'] = True
            result['message'] = f"{module.params['name']} deleted."
            module.exit_json(**result)
        except Exception as e:
            result['changed'] = False
            result['failed'] = True
            result['message'] = f"Error deleting {module.params['name']}.  Exception detail: {e}."
            module.fail_json(msg='Failed to delete file.', **result)

    result['filename'] = module.params['name']

    # if 'content' not in module.params:
    #     module.params['content'] = ""

    if module.params['state'] == 'deleted':
        handle_deleted(module)
    elif module.params['state'] == 'overridden':
        handle_overridden(module)
    elif module.params['state'] == 'merged' and module.params['content'] == "":
        handle_merged_no_content(module)
    elif module.params['state'] == 'merged' and module.params['content'] != "":
        handle_merged_with_content(module)
    else:
        result['changed'] = False
        result['failed'] = True
        result['message'] = f"Unknown state: ({module.params['state']}).  Must be one of 'merged', 'overridden', 'deleted'."
        module.fail_json(msg='Bad state.', **result)

def main():
    run_module()


if __name__ == '__main__':
    main()
