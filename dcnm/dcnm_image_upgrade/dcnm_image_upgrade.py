#!/usr/bin/python
#
# Copyright (c) 2020-2024 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Classes and methods for Ansible support of Nexus image upgrade.

Ansible states "merged", "deleted", and "query" are implemented.

merged: attach image policy to one or more devices
deleted: delete image policy from one or more devices
query: return image policy details for one or more devices
"""
from __future__ import absolute_import, division, print_function

import copy
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm_image_upgrade_lib import (
    NdfcAnsibleImageUpgradeCommon,
    NdfcImageValidate,
    NdfcImagePolicies,
    NdfcImagePolicyAction,
    NdfcImageInstallOptions,
    NdfcImageUpgrade,
    NdfcSwitchDetails,
    NdfcSwitchIssuDetailsByIpAddress
)
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send,
    validate_list_of_dicts,
)

__metaclass__ = type
__author__ = "Cisco Systems, Inc."

DOCUMENTATION = """
---
module: dcnm_image_upgrade
short_description: Attach, detach, and query device image policies.
version_added: "0.9.0"
description:
    - Attach, detach, and query device image policies.
author: Cisco Systems, Inc.
options:
    state:
        description:
        - The state of DCNM after module completion.
        - I(merged) and I(query) are the only states supported.
        type: str
        choices:
        - merged
        - deleted
        - query
        default: merged
    config:
        description:
        - A dictionary containing the image policy configuration.
        type: dict
        suboptions:
            policy:
                description:
                - Image policy name
                type: str
                required: true
                default: False
            stage:
                description:
                - Stage (True) or unstage (False) an image policy
                type: bool
                required: false
                default: True
            upgrade:
                description:
                - Enable (True) or disable (False) image upgrade
                type: bool
                required: false
                default: True
            switches:
                description:
                - A list of devices to attach the image policy to.
                type: list
                elements: dict
                required: true
                suboptions:
                    ip_address:
                        description:
                        - The IP address of the device to which the policy will be attached.
                        type: str
                        required: true
                    policy:
                        description:
                        - The image policy name to attach to the device.
                        type: str
                        required: false
                        default: The global policy name
                    stage:
                        description:
                        - Stage (True) or unstage (False) an image policy
                        - Overrides the global stage parameter
                        type: bool
                        required: false
                        default: True
                    upgrade:
                        description:
                        - Enable (True) or disable (False) image upgrade
                        - Overrides the global upgrade parameter
                        type: bool
                        required: false
                        default: True
"""

EXAMPLES = """
# This module supports the following states:
#
# merged:
#   Attach image policy to one or more devices.
#
# query:
#   Return image policy details for one or more devices.
#   
# deleted:
#   Delete image policy from one or more devices
#

# Attach image policy NR3F to two devices
# Stage the image on both devices but do not upgrade
    -   name: stage/upgrade devices
        cisco.dcnm.dcnm_image_upgrade:
            state: merged
            config:
                policy: NR3F
                stage: true
                upgrade: false
                switches:
                -   ip_address: 192.168.1.1
                -   ip_address: 192.168.1.2

# Attach image policy NR1F to device 192.168.1.1
# Attach image policy NR2F to device 192.168.1.2
# Stage the image on device 192.168.1.1, but do not upgrade
# Stage the image and upgrade device 192.168.1.2
    -   name: stage/upgrade devices
        cisco.dcnm.dcnm_image_upgrade:
            state: merged
            config:
                switches:
                    - ip_address: 192.168.1.1
                    policy: NR1F
                    stage: true
                    upgrade: false
                    - ip_address: 192.168.1.2
                    policy: NR2F
                    stage: true
                    upgrade: true

# Detach image policy NR3F from two devices
    -   name: stage/upgrade devices
        cisco.dcnm.dcnm_image_upgrade:
            state: deleted
            config:
                policy: NR3F
                switches:
                -   ip_address: 192.168.1.1
                -   ip_address: 192.168.1.2

"""


class NdfcAnsibleImageUpgrade(NdfcAnsibleImageUpgradeCommon):
    """
    Ansible support for image policy attach, detach, and query.
    """

    def __init__(self, module):
        super().__init__(module)
        self.class_name = self.__class__.__name__
        # populated in self._build_policy_attach_payload()
        self.payloads = []

        self.config = module.params.get("config")
        if not isinstance(self.config, dict):
            msg = "expected dict type for self.config. "
            msg = +f"got {type(self.config).__name__}"
            self.module.fail_json(msg)

        self.check_mode = False
        self.validated = []
        self.have_create = []
        self.want_create = []
        self.need = []
        self.diff_save = {}
        self.query = []
        self.result = dict(changed=False, diff=[], response=[])

        self.mandatory_global_keys = {"switches"}
        self.mandatory_switch_keys = {"ip_address"}

        if not self.mandatory_global_keys.issubset(self.config):
            msg = f"{self.class_name}.__init__: "
            msg += "Missing mandatory key(s) in playbook global config. "
            msg += f"expected {self.mandatory_global_keys}, "
            msg += f"got {self.config.keys()}"
            self.module.fail_json(msg)

        if self.config["switches"] is None:
            msg = f"{self.class_name}.__init__: "
            msg += "missing list of switches in playbook config."
            self.module.fail_json(msg)

        for switch in self.config["switches"]:
            if not self.mandatory_switch_keys.issubset(switch):
                msg = f"{self.class_name}.__init__: "
                msg += f"missing mandatory key(s) in playbook switch config. "
                msg += f"expected {self.mandatory_switch_keys}, "
                msg += f"got {switch.keys()}"
                self.module.fail_json(msg)

        self._init_defaults()

        self.switch_details = NdfcSwitchDetails(self.module)
        self.image_policies = NdfcImagePolicies(self.module)

    def _init_defaults(self):
        self.defaults = {}
        self.defaults["stage"] = True
        self.defaults["upgrade"] = True

    def get_have(self):
        """
        Caller: main()

        Determine current switch ISSU state on NDFC
        """
        self.have = NdfcSwitchIssuDetailsByIpAddress(self.module)

    def get_want(self):
        """
        Caller: main()

        Update self.want_create for all switches defined in the playbook
        """
        self._merge_global_and_switch_configs(self.config)
        self._validate_switch_configs()
        if not self.switch_configs:
            return
        self.want_create = self.switch_configs

    def _get_idempotent_want(self, want):
        """
        Return an itempotent want item based on the have item contents.

        The have item is obtained from an instance of NdfcSwitchIssuDetails
        created in self.get_have().

        Structure:

        {
            "ip_address": "192.168.1.1",
            "policy": "NR1F",
            "policy_changed": False,
            "stage": True,
            "upgrade": True
        }

        Caller: self.get_need_merged()
        """
        self.have.ip_address = want["ip_address"]

        want["policy_changed"] = True
        # The switch does not have an image policy attached
        # Return the want item as-is with policy_changed = True
        if self.have.serial_number is None:
            return want
        # The switch has an image policy attached which is
        # different from the want policy.
        # Return the want item as-is with policy_changed = True
        if want["policy"] != self.have.policy:
            return want

        idempotent_want = {}
        # Give an indication to the caller that the policy has not changed
        # We can use this later to determine if we need to do anything in
        # the case where the image is already staged and/or upgraded.
        idempotent_want["policy_changed"] = False
        idempotent_want["policy"] = want["policy"]
        idempotent_want["ip_address"] = want["ip_address"]
        idempotent_want["stage"] = want["stage"]
        idempotent_want["upgrade"] = want["upgrade"]

        # if the image is already staged, don't stage it again
        if self.have.image_staged == "Success":
            idempotent_want["stage"] = False
        # if the image is already upgraded, don't upgrade it again
        if self.have.upgrade == "Success":
            idempotent_want["upgrade"] = False
        return idempotent_want

    def get_need_merged(self):
        """
        Caller: main()

        For merged state, populate self.need list() with items from
        our want list that are not in our have list.  These items will be sent
        to NDFC.
        """
        need = []

        for want_create in self.want_create:
            self.have.ip_address = want_create["ip_address"]
            if self.have.serial_number is not None:
                idempotent_want = self._get_idempotent_want(want_create)
                if (
                    idempotent_want["policy_changed"] is False
                    and idempotent_want["stage"] is False
                    and idempotent_want["upgrade"] is False
                ):
                    continue
                need.append(idempotent_want)
        self.need = need
        msg = f"REMOVE: {self.class_name}.get_need_merged: "
        msg += f"need: {self.need}"
        self.log_msg(msg)

    def get_need_deleted(self):
        """
        Caller: main()

        For deleted state, populate self.need list() with items from our want
        list that are not in our have list.  These items will be sent to NDFC.
        """
        need = []
        for want in self.want_create:
            self.have.ip_address = want["ip_address"]
            if self.have.serial_number is None:
                continue
            if self.have.policy is None:
                continue
            need.append(want)
        self.need = need

    def get_need_query(self):
        """
        Caller: main()

        For query state, populate self.need list() with all items from our want
        list.  These items will be sent to NDFC.
        """
        need = []
        for want in self.want_create:
            need.append(want)
        self.need = need

    @staticmethod
    def _build_params_spec_for_merged_state():
        """
        Build the specs for the parameters expected when state == merged.

        Caller: _validate_input_for_merged_state()
        Return: params_spec, a dictionary containing the set of
                parameter specifications.
        """
        params_spec = {}
        params_spec.update(policy=dict(required=False, type="str"))
        params_spec.update(upgrade=dict(required=False, type="bool", default=True))
        params_spec.update(stage=dict(required=False, type="bool", default=True))
        return params_spec

    def validate_input(self):
        """
        Caller: main()

        Validate the playbook parameters
        """
        state = self.params["state"]

        if state not in ["merged", "deleted", "query"]:
            msg = f"Only deleted, merged, and query states are supported. Got state {state}"
            self.module.fail_json(msg)

        if state == "merged":
            self._validate_input_for_merged_state()
            return
        if state == "deleted":
            self._validate_input_for_deleted_state()
            return
        if state == "query":
            self._validate_input_for_query_state()
            return

    def _validate_input_for_merged_state(self):
        """
        Caller: self.validate_input()

        Validate that self.config contains appropriate values for merged state
        """
        params_spec = self._build_params_spec_for_merged_state()
        if not self.config:
            msg = "config: element is mandatory for state merged"
            self.module.fail_json(msg)

        valid_params, invalid_params = validate_list_of_dicts(
            self.config.get("switches"), params_spec, self.module
        )
        # We're not using self.validated. Keeping this to avoid
        # linter error due to non-use of valid_params
        self.validated = copy.deepcopy(valid_params)

        if invalid_params:
            msg = "Invalid parameters in playbook: "
            msg += f"{','.join(invalid_params)}"
            self.module.fail_json(msg)

    def _validate_input_for_deleted_state(self):
        """
        Caller: self.validate_input()

        Validate that self.config contains appropriate values for deleted state

        NOTES:
        1. This is currently identical to _validate_input_for_merged_state()
        2. Adding in case there are differences in the future
        """
        params_spec = self._build_params_spec_for_merged_state()
        if not self.config:
            msg = "config: element is mandatory for state deleted"
            self.module.fail_json(msg)

        valid_params, invalid_params = validate_list_of_dicts(
            self.config.get("switches"), params_spec, self.module
        )
        # We're not using self.validated. Keeping this to avoid
        # linter error due to non-use of valid_params
        self.validated = copy.deepcopy(valid_params)

        if invalid_params:
            msg = "Invalid parameters in playbook: "
            msg += f"{','.join(invalid_params)}"
            self.module.fail_json(msg)

    def _validate_input_for_query_state(self):
        """
        Caller: self.validate_input()

        Validate that self.config contains appropriate values for query state

        NOTES:
        1. This is currently identical to _validate_input_for_merged_state()
        2. Adding in case there are differences in the future
        """
        params_spec = self._build_params_spec_for_merged_state()
        if not self.config:
            msg = "config: element is mandatory for state query"
            self.module.fail_json(msg)

        valid_params, invalid_params = validate_list_of_dicts(
            self.config.get("switches"), params_spec, self.module
        )
        # We're not using self.validated. Keeping this to avoid
        # linter error due to non-use of valid_params
        self.validated = copy.deepcopy(valid_params)

        if invalid_params:
            msg = "Invalid parameters in playbook: "
            msg += f"{','.join(invalid_params)}"
            self.module.fail_json(msg)

    def _merge_global_and_switch_configs(self, config):
        """
        Merge the global config with each switch config and return
        a dict of switch configs keyed on switch ip_address.

        Merge rules:
        1.  switch_config takes precedence over global_config.
        2.  If switch_config is missing a parameter, use parameter
            from global_config.
        3.  If a switch_config has a parameter, use it.
        4.  If global_config and switch_config are both missing an
            optional parameter, use the parameter's default value.
        5.  If global_config and switch_config are both missing a
            mandatory parameter, fail.
        """
        global_config = {}
        global_config["policy"] = config.get("policy")
        global_config["stage"] = config.get("stage")
        global_config["upgrade"] = config.get("upgrade")

        self.switch_configs = []
        if not config.get("switches"):
            msg = "playbook is missing list of switches"
            self.module.fail_json(msg)
        for switch in config["switches"]:
            self.switch_configs.append(global_config | switch)

    def _validate_switch_configs(self):
        """
        Ensure mandatory parameters are present for each switch
            - fail_json if this isn't the case
        Set defaults for missing optional parameters

        Callers:
            - self.get_want
        """
        for switch in self.switch_configs:
            if not switch.get("ip_address"):
                msg = "playbook is missing ip_address for at least one switch"
                self.module.fail_json(msg)
            # for query state, the only mandatory parameter is ip_address
            # so skip the remaining checks
            if self.params.get("state") == "query":
                continue
            if switch.get("policy") is None:
                msg = "playbook is missing image policy for switch "
                msg += f"{switch.get('ip_address')} "
                msg += "and global image policy is not defined."
                self.module.fail_json(msg)
            if switch.get("stage") is None:
                switch["stage"] = self.defaults["stage"]
            if switch.get("upgrade") is None:
                switch["upgrade"] = self.defaults["upgrade"]

    def _build_policy_attach_payload(self):
        """
        Build the payload for the policy attach request to NDFC
        Verify that the image policy exists on NDFC
        Verify that the image policy supports the switch platform

        Callers:
            - self.handle_merged_state
        """
        self.payloads = []
        for switch in self.need:
            if switch.get("policy_changed") is False:
                continue
            self.switch_details.ip_address = switch.get("ip_address")
            self.image_policies.policy_name = switch.get("policy")

            # Fail if the image policy does not exist.
            # Image policy creation is handled by a different module.
            if self.image_policies.name is None:
                msg = f"policy {switch.get('policy')} does not exist on NDFC"
                self.module.fail_json(msg)

            # Fail if the image policy does not support the switch platform
            if self.switch_details.platform not in self.image_policies.platform:
                msg = f"policy {switch.get('policy')} does not support platform "
                msg += f"{self.switch_details.platform}. {switch.get('policy')} "
                msg += "supports the following platform(s): "
                msg += f"{self.image_policies.platform}"
                self.module.fail_json(msg)

            payload = {}
            payload["policyName"] = self.image_policies.name
            # switch_details.host_name is always None in 12.1.2e
            # so we're using logical_name instead
            payload["hostName"] = self.switch_details.logical_name
            payload["ipAddr"] = self.switch_details.ip_address
            payload["platform"] = self.switch_details.platform
            payload["serialNumber"] = self.switch_details.serial_number
            # payload["bootstrapMode"] = switch.get('bootstrap_mode')

            for item in payload:
                if payload[item] is None:
                    msg = f"Unable to determine {item} for switch {switch.get('ip_address')}. "
                    msg += "Please verify that the switch is managed by NDFC."
                    self.module.fail_json(msg)
            self.payloads.append(payload)

    def _send_policy_attach_payload(self):
        """
        Send the policy attach payload to NDFC and handle the response

        Callers:
            - self.handle_merged_state
        """
        if len(self.payloads) == 0:
            return
        path = self.endpoints["policy_attach"]["path"]
        verb = self.endpoints["policy_attach"]["verb"]
        payload = {}
        payload["mappingList"] = self.payloads
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_response(response, verb)

        if not result["success"]:
            self._failure(response)

    def _stage_images(self, serial_numbers):
        """
        Initiate image staging to the switch(es) associated with serial_numbers

        Callers:
        - handle_merged_state
        """
        instance = NdfcImageStage(self.module)
        instance.serial_numbers = serial_numbers
        instance.commit()

    def _validate_images(self, serial_numbers):
        """
        Validate the image staged to the switch(es)

        Callers:
        - handle_merged_state
        """
        instance = NdfcImageValidate(self.module)
        instance.serial_numbers = serial_numbers
        # TODO:2 Discuss with Mike/Shangxin - NdfcImageValidate.non_disruptive
        # Should we add this option to the playbook?
        # It's supported in NdfcImageValidate with default of False
        # instance.non_disruptive = False
        instance.commit()

    def _verify_install_options(self, devices):
        """
        Verify that the install options for the switch(es) are valid

        Callers:
        - self.handle_merged_state
        """
        if len(devices) == 0:
            return
        install_options = NdfcImageInstallOptions(self.module)
        for device in devices:
            install_options.serial_number = device["serial_number"]
            install_options.policy_name = device["policy_name"]
            install_options.refresh()
            if install_options.status not in ["Success", "Skipped"]:
                msg = f"Got install options status {install_options.status} "
                msg += f"for device {device['serial_number']} "
                msg += f"with ip_address {device['ip_address']}."
                self.module.fail_json(msg)

    def _upgrade_images(self, devices):
        """
        Upgrade the switch(es) to the currently-validated image

        Callers:
        - handle_merged_state
        """
        upgrade = NdfcImageUpgrade(self.module)
        upgrade.devices = devices
        # TODO:2 Discuss with Mike/Shangxin. Upgrade option handling mutex options.
        # I'm leaning toward doing this in NdfcImageUpgrade().validate_options()
        # which would cover the various scenarios and fail_json() on invalid
        # combinations.
        # For epld upgrade disrutive must be True and non_disruptive must be False
        # upgrade.epld_upgrade = True
        # upgrade.disruptive = True
        # upgrade.non_disruptive = False
        # upgrade.epld_module = "ALL"
        upgrade.commit()

    def handle_merged_state(self):
        """
        Update the switch policy if it has changed.
        Stage the image if requested.
        Upgrade the image if requested.

        Caller: main()
        """
        # TODO:1 Replace these with NdfcImagePolicyAction
        # See commented code below
        self._build_policy_attach_payload()
        self._send_policy_attach_payload()

        # Use (or not) below for policy attach/detach
        # instance = NdfcImagePolicyAction(self.module)
        # instance.policy_name = "NR3F"
        # instance.action = "attach" # or detach
        # instance.serial_numbers = ["FDO211218GC", "FDO211218HH"]
        # instance.commit()
        # policy_attach_devices = []
        # policy_detach_devices = []

        stage_devices = []
        validate_devices = []
        upgrade_devices = []
        for switch in self.need:
            msg = f"REMOVE: {self.class_name}.handle_merged_state: switch: {switch}"
            self.log_msg(msg)
            self.switch_details.ip_address = switch.get("ip_address")
            device = {}
            device["serial_number"] = self.switch_details.serial_number
            self.have.ip_address = self.switch_details.ip_address
            device["policy_name"] = switch.get("policy")
            device["ip_address"] = self.switch_details.ip_address
            if switch.get("stage") is not False:
                stage_devices.append(device["serial_number"])
            # TODO:2 Discuss with Mike/Shangxin.  Add validate option?
            # Currently, we always validate the image after staging
            # Replace with the below if we add a validate option
            # if switch.get("validate") is not False:
            #     validate_devices.append(device["serial_number"])
            validate_devices.append(device["serial_number"])
            if switch.get("upgrade") is not False:
                upgrade_devices.append(device)

        self.log_msg(
            f"REMOVE: {self.class_name}.handle_merged_state: stage_devices: {stage_devices}"
        )
        self._stage_images(stage_devices)
        self.log_msg(
            f"REMOVE: {self.class_name}.handle_merged_state: validate_devices: {validate_devices}"
        )
        self._validate_images(validate_devices)
        self.log_msg(
            f"REMOVE: {self.class_name}.handle_merged_state: upgrade_devices: {upgrade_devices}"
        )
        self._verify_install_options(upgrade_devices)
        self._upgrade_images(upgrade_devices)

    def handle_deleted_state(self):
        """
        Delete the image policy from the switch(es)

        Caller: main()
        """
        msg = f"REMOVE: {self.class_name}.handle_deleted_state: "
        msg += f"Entered with self.need {self.need}"
        self.log_msg(msg)
        detach_policy_devices = {}
        for switch in self.need:
            self.switch_details.ip_address = switch.get("ip_address")
            self.image_policies.policy_name = switch.get("policy")
            # if self.image_policies.name is None:
            #     continue
            if self.image_policies.name not in detach_policy_devices:
                detach_policy_devices[self.image_policies.policy_name] = []
            detach_policy_devices[self.image_policies.policy_name].append(
                self.switch_details.serial_number
            )
        msg = f"REMOVE: {self.class_name}.handle_deleted_state: "
        msg += f"detach_policy_devices: {detach_policy_devices}"
        self.log_msg(msg)

        if len(detach_policy_devices) == 0:
            self.result = dict(changed=False, diff=[], response=[])
            return
        instance = NdfcImagePolicyAction(self.module)
        for policy_name in detach_policy_devices:
            msg = f"REMOVE: {self.class_name}.handle_deleted_state: "
            msg += f"detach policy_name: {policy_name}"
            msg += f" from devices: {detach_policy_devices[policy_name]}"
            self.log_msg(msg)
            instance.policy_name = policy_name
            instance.action = "detach"
            instance.serial_numbers = detach_policy_devices[policy_name]
            instance.commit()

    def handle_query_state(self):
        """
        Return the ISSU state of the switch(es) listed in the playbook

        Caller: main()
        """
        instance = NdfcSwitchIssuDetailsByIpAddress(self.module)
        msg = f"REMOVE: {self.class_name}.handle_query_state: "
        msg += f"Entered. self.need {self.need}"
        self.log_msg(msg)
        query_devices = []
        for switch in self.need:
            instance.ip_address = switch.get("ip_address")
            if instance.filtered_data is None:
                continue
            query_devices.append(instance.filtered_data)
        msg = f"REMOVE: {self.class_name}.handle_query_state: "
        msg += f"query_policies: {query_devices}"
        self.log_msg(msg)
        self.result["response"] = query_devices
        self.result["diff"] = []
        self.result["changed"] = False


    def _failure(self, resp):
        """
        Caller: self.attach_policies()

        This came from dcnm_inventory.py, but doesn't seem to be correct
        for the case where resp["DATA"] does not exist?

        If resp["DATA"] does not exist, the contents of the
        if block don't seem to actually do anything:
            - data will be None
            - Hence, data.get("stackTrace") will also be None
            - Hence, data.update() and res.update() are never executed

        So, the only two lines that will actually ever be executed are
        the happy path:

        res = copy.deepcopy(resp)
        self.module.fail_json(msg=res)
        """
        res = copy.deepcopy(resp)

        if not resp.get("DATA"):
            data = copy.deepcopy(resp.get("DATA"))
            if data.get("stackTrace"):
                data.update(
                    {"stackTrace": "Stack trace is hidden, use '-vvvvv' to print it"}
                )
                res.update({"DATA": data})

        self.module.fail_json(msg=res)




def main():
    """main entry point for module execution"""

    element_spec = dict(
        config=dict(required=True, type="dict"),
        state=dict(default="merged", choices=["merged", "deleted", "query"]),
    )

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)
    dcnm_module = NdfcAnsibleImageUpgrade(module)
    dcnm_module.validate_input()
    dcnm_module.get_have()
    dcnm_module.get_want()

    if module.params["state"] == "merged":
        dcnm_module.get_need_merged()
    elif module.params["state"] == "deleted":
        dcnm_module.get_need_deleted()
    elif module.params["state"] == "query":
        dcnm_module.get_need_query()

    if module.params["state"] == "query":
        dcnm_module.result["changed"] = False
    if module.params["state"] in ["merged", "deleted"]:
        if dcnm_module.need:
            dcnm_module.result["changed"] = True
        else:
            module.exit_json(**dcnm_module.result)

    if module.check_mode:
        dcnm_module.result["changed"] = False
        module.exit_json(**dcnm_module.result)

    if dcnm_module.need:
        if module.params["state"] == "merged":
            dcnm_module.handle_merged_state()
        elif module.params["state"] == "deleted":
            dcnm_module.handle_deleted_state()
        elif module.params["state"] == "query":
            dcnm_module.handle_query_state()

    module.exit_json(**dcnm_module.result)


if __name__ == "__main__":
    main()
