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
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send,
    dcnm_version_supported,
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

"""

class DcnmImageUpgradeCommon:
    """
    Base class for the following classes in this file:

    DcnmImageUpgrade()

    """
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.debug = True
        self.fd = None
        self.logfile = "/tmp/dcnm_image_upgrade.log"
        self._init_endpoints()

    def _init_endpoints(self):
        self.endpoint_bootflash = "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imagemgnt/bootFlash"
        self.endpoint_image_management = "/appcenter/cisco/ndfc/api/v1/imagemanagement"
        self.endpoint_staging_management = f"{self.endpoint_image_management}/rest/stagingmanagement"
        self.endpoint_image_upgrade = f"{self.endpoint_image_management}/rest/imageupgrade"
        self.endpoint_package_mgnt = f"{self.endpoint_image_management}/rest/packagemgnt"
        self.endpoint_policy_mgnt = f"{self.endpoint_image_management}/rest/policymgnt"
        self.endpoint_lan_fabric = "/appcenter/cisco/ndfc/api/v1/lan-fabric"
        self.endpoints = {}
        self.endpoints["bootflash_info"] = {}
        self.endpoints["image_stage"] = {}
        self.endpoints["image_upgrade"] = {}
        self.endpoints["image_validate"] = {}
        self.endpoints["issu_info"] = {}
        self.endpoints["policies_attached_info"] = {}
        self.endpoints["policies_info"] = {}
        self.endpoints["policy_attach"] = {}
        self.endpoints["policy_create"] = {}
        self.endpoints["policy_detach"] = {}
        self.endpoints["policy_info"] = {}
        self.endpoints["stage_info"] = {}
        self.endpoints["switches_info"] = {}

        self.endpoints["bootflash_info"]["path"] = f"{self.endpoint_bootflash}/bootflash-info"
        self.endpoints["bootflash_info"]["verb"] = "GET"

        self.endpoints["image_stage"]["path"] = f"{self.endpoint_staging_management}/stage-image"
        self.endpoints["image_stage"]["verb"] = "POST"

        self.endpoints["image_upgrade"]["path"] = f"{self.endpoint_image_upgrade}/upgrade-image"
        self.endpoints["image_upgrade"]["verb"] = "POST"

        self.endpoints["image_validate"]["path"] = f"{self.endpoint_staging_management}/validate-image"
        self.endpoints["image_validate"]["verb"] = "POST"

        self.endpoints["issu_info"]["path"] = f"{self.endpoint_package_mgnt}/issu"
        self.endpoints["issu_info"]["verb"] = "GET"

        self.endpoints["policies_attached_info"]["path"] = f"{self.endpoint_policy_mgnt}/all-attached-policies"
        self.endpoints["policies_attached_info"]["verb"] = "GET"

        self.endpoints["policies_info"]["path"] = f"{self.endpoint_policy_mgnt}/policies"
        self.endpoints["policies_info"]["verb"] = "GET"

        self.endpoints["policy_attach"]["path"] = f"{self.endpoint_policy_mgnt}/attach-policy"
        self.endpoints["policy_attach"]["verb"] = "POST"

        self.endpoints["policy_create"]["path"] = f"{self.endpoint_policy_mgnt}/platform-policy"
        self.endpoints["policy_create"]["verb"] = "POST"

        self.endpoints["policy_detach"]["path"] = f"{self.endpoint_policy_mgnt}/detach-policy"
        self.endpoints["policy_detach"]["verb"] = "DELETE"

        # Replace __POLICY_NAME__ with the policy_name to query
        # e.g. path.replace("__POLICY_NAME__", "NR1F")
        self.endpoints["policy_info"]["path"] = f"{self.endpoint_policy_mgnt}/edit-policy-get/__POLICY_NAME__"
        self.endpoints["policy_info"]["verb"] = "GET"

        self.endpoints["stage_info"]["path"] = f"{self.endpoint_staging_management}/stage-info"
        self.endpoints["stage_info"]["verb"] = "GET"

        self.endpoints["switches_info"]["path"] = f"{self.endpoint_lan_fabric}/rest/inventory/allswitches"
        self.endpoints["switches_info"]["verb"] = "GET"

        
    def _handle_get_response(self, response):
        """
        Caller:
            - self.get_have()
        Handle NDFC responses to GET requests
        Returns: dict() with the following keys:
        - found:
            - False, if request error was "Not found" and RETURN_CODE == 404
            - True otherwise
        - success:
            - False if RETURN_CODE != 200 or MESSAGE != "OK"
            - True otherwise
        """
        result = {}
        success_return_codes = {200, 404}
        if (
            response.get("RETURN_CODE") == 404
            and response.get("MESSAGE") == "Not Found"
        ):
            result["found"] = False
            result["success"] = True
            return result
        if (
            response.get("RETURN_CODE") not in success_return_codes
            or response.get("MESSAGE") != "OK"
        ):
            result["found"] = False
            result["success"] = False
            return result
        result["found"] = True
        result["success"] = True
        return result

    def _handle_post_put_response(self, response, verb):
        """
        Caller:
            - self.attach_policies()

        Handle POST, PUT responses from NDFC.

        Returns: dict() with the following keys:
        - changed:
            - True if changes were made to NDFC
            - False otherwise
        - success:
            - False if RETURN_CODE != 200 or MESSAGE != "OK"
            - True otherwise

        """
        valid_verbs = {"POST", "PUT"}
        if verb not in valid_verbs:
            msg = f"invalid verb {verb}. "
            msg += f"expected one of: {','.join(sorted(valid_verbs))}"
            self.module.fail_json(msg=msg)

        result = {}
        if response.get("MESSAGE") != "OK":
            result["success"] = False
            result["changed"] = False
            return result
        if response.get("ERROR"):
            result["success"] = False
            result["changed"] = False
            return result
        result["success"] = True
        result["changed"] = True
        return result

    def log_msg(self, msg):
        """
        used for debugging. disable this when committing to main
        """
        if self.debug is False:
            return
        if self.fd is None:
            try:
                self.fd = open(f"{self.logfile}", "a+", encoding="UTF-8")
            except IOError as err:
                msg = f"error opening logfile {self.logfile}. "
                msg += f"detail: {err}"
                self.module.fail_json(msg=msg)

        self.fd.write(msg)
        self.fd.write("\n")
        self.fd.flush()

    def make_boolean(self, value):
        """
        Return value converted to boolean, if possible.
        Return value, if value cannot be converted.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() in ["true", "yes"]:
                return True
            if value.lower() in ["false", "no"]:
                return False
        return value

class DcnmImageUpgrade(DcnmImageUpgradeCommon):
    """
    Ansible support for image policy attach, detach, and query.
    """
    def __init__(self, module):
        super().__init__(module)

        # populated in self.build_policy_attach_payload()
        self.payloads = []

        self.config = module.params.get("config")
        if not isinstance(self.config, dict):
            msg = "expected dict type for self.config. "
            msg =+ f"got {type(self.config).__name__}"
            self.module.fail_json(msg=msg)

        self.check_mode = False
        self.validated = []
        self.have_create = []
        self.want_create = []
        self.diff_create = []
        self.diff_save = {}
        self.query = []
        self.result = dict(changed=False, diff=[], response=[])

        self.controller_version = dcnm_version_supported(self.module)
        self.nd = self.controller_version >= 12

        self.mandatory_global_keys = {"policy", "switches"}
        self.mandatory_switch_keys = {"ip_address"}

        if not self.mandatory_global_keys.issubset(self.config):
            msg = f"missing mandatory key(s) in playbook config. "
            msg += f"expected {self.mandatory_keys}, "
            msg += f"got {self.config.keys()}"
            self.module.fail_json(msg=msg)

        for switch in self.config["switches"]:
            if not self.mandatory_switch_keys.issubset(switch):
                msg = f"missing mandatory key(s) in playbook switch config. "
                msg += f"expected {self.mandatory_switch_keys}, "
                msg += f"got {switch.keys()}"
                self.module.fail_json(msg=msg)

        self._init_defaults()

        self.switch_details = DcnmSwitchDetails(self.module)
        self.image_policies = DcnmImagePolicies(self.module)

    def _init_defaults(self):
        self.defaults = {}
        self.defaults["stage"] = True
        self.defaults["upgrade"] = True

    def get_have(self):
        """
        Caller: main()

        Determine current switch ISSU state on NDFC
        """
        self.have = DcnmSwitchIssuDetails(self.module)
        # path = self.endpoints["policies_info"]["path"]
        # verb = self.endpoints["policies_info"]["verb"]
        # self.have = dcnm_send(self.module, verb, path)
        # result = self._handle_get_response(self.have)
        # if not result["success"]:
        #     msg = "Unable to retrieve image policy information from NDFC"
        #     self.module.fail_json(msg=msg)

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

        The have item is obtained from an instance of DcnmSwitchIssuDetails
        created in self.get_have().

        Caller: self.get_diff_merge()
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

    def get_diff_merge(self):
        """
        Caller: main()

        Populates self.diff_create list() with items from our want list
        that are not in our have list.  These items will be sent to NDFC.
        """
        diff_create = []

        for want_create in self.want_create:
            self.have.ip_address = want_create["ip_address"]
            if self.have.serial_number is not None:
                idempotent_want = self._get_idempotent_want(want_create)
                if (idempotent_want["policy_changed"] is False and
                    idempotent_want["stage"] is False and
                    idempotent_want["upgrade"] is False):
                    continue
                diff_create.append(idempotent_want)
        self.diff_create = diff_create
        self.log_msg(f"diff_create: {self.diff_create}")

    @staticmethod
    def _build_params_spec_for_merged_state():
        """
        Build the specs for the parameters expected when state == merged.

        Caller: _validate_input_for_merged_state()
        Return: params_spec, a dictionary containing the set of
                parameter specifications.
        """
        params_spec = {}
        params_spec.update(
            policy=dict(
            required=True,
            type="str")
        )
        params_spec.update(
            upgrade=dict(
            required=False,
            type="bool",
            default=True)
        )
        params_spec.update(
            stage=dict(
            required=False,
            type="bool",
            default=True)
        )
        return params_spec

    def validate_input(self):
        """
        Caller: main()

        Validate the playbook parameters
        Build the payloads for each fabric
        """
        state = self.params["state"]

        # TODO:2 remove this when we implement query state
        if state != "merged":
            msg = f"Only merged state is supported. Got state {state}"
            self.module.fail_json(msg=msg)

        if state == "merged":
            self._validate_input_for_merged_state()
            return

    def _validate_input_for_merged_state(self):
        """
        Caller: self._validate_input()

        Validate that self.config contains appropriate values for merged state
        """
        params_spec = self._build_params_spec_for_merged_state()
        msg = None
        if not self.config:
            msg = "config: element is mandatory for state merged"
            self.module.fail_json(msg=msg)

        valid_params, invalid_params = validate_list_of_dicts(
            self.config.get("switches"), params_spec, self.module
        )
        # We're not using self.validated. Keeping this to avoid
        # linter error due to non-use of valid_params
        self.validated = copy.deepcopy(valid_params)

        if invalid_params:
            msg = "Invalid parameters in playbook: "
            msg += f"{','.join(invalid_params)}"
            self.module.fail_json(msg=msg)
        
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
        global_config['policy'] = config.get('policy')
        global_config['stage'] = config.get('stage')
        global_config['upgrade'] = config.get('upgrade')

        self.switch_configs = []
        if not config.get('switches'):
            msg = "playbook is missing list of switches"
            self.module.fail_json(msg)
        for switch in config['switches']:
            self.switch_configs.append(global_config | switch)

    def _validate_switch_configs(self):
        for switch in self.switch_configs:
            if not switch.get('ip_address'):
                msg = "playbook is missing ip_address for at least one switch"
                self.module.fail_json(msg)
            if not switch.get('policy'):
                msg = "playbook is missing image policy for switch "
                msg += f"{switch.get('ip_address')} "
                msg = "and global image policy is not defined"
                self.module.fail_json(msg)
            if switch.get('stage') is None:
                switch['stage'] = self.defaults["stage"]
            if switch.get('upgrade') is None:
                switch['upgrade'] = self.defaults["upgrade"]

    def attach_image_management_policy(self):
        """
            {
                "mappingList":
                    [
                        {
                            "policyName": "MyPolicy",
                            "hostName": "N9K_62",
                            "ipAddr": "172.23.258.66",
                            "platform": "N7K",
                            "serialNumber": "FDO2338082P",
                            "bootstrapMode": "true"
                        }
                    ],
                "stageValidate": true
            }
        """
        pass

    def build_policy_attach_payload(self):
        self.payloads = []
        for switch in self.diff_create:
            if switch.get('policy_changed') is False:
                continue
            self.switch_details.ip_address = switch.get('ip_address')
            self.image_policies.policy_name = switch.get('policy')

            # Fail if the image policy does not exist.
            # Image policy creation is handled by a different module.
            if self.image_policies.name is None:
                msg = f"policy {switch.get('policy')} does not exist on NDFC"
                self.module.fail_json(msg=msg)

            # Fail if the image policy does not support the switch platform
            if self.switch_details.platform not in self.image_policies.platform:
                msg = f"policy {switch.get('policy')} does not support platform "
                msg += f"{self.switch_details.platform}. {switch.get('policy')} "
                msg += "supports the following platform(s): "
                msg += f"{self.image_policies.platform}"
                self.module.fail_json(msg=msg)

            payload = {}
            payload["policyName"] = self.image_policies.name
            payload["hostName"] = self.switch_details.hostname
            payload["ipAddr"] = self.switch_details.ip_address
            payload["platform"] = self.switch_details.platform
            payload["serialNumber"] = self.switch_details.serial_number
            #payload["bootstrapMode"] = switch.get('bootstrap_mode')

            for item in payload:
                if payload[item] is None:
                    msg = f"Unable to determine {item} for switch {switch.get('ip_address')}. "
                    msg += f"Please verify that the switch is managed by NDFC."
                    self.module.fail_json(msg=msg)
            self.payloads.append(payload)

    def send_policy_attach_payload(self):
        """
        Send the policy attach payload to NDFC and handle the response
        """
        if len(self.payloads) == 0:
            return
        path = self.endpoints["policy_attach"]["path"]
        verb = self.endpoints["policy_attach"]["verb"]
        payload = {}
        payload["mappingList"] = self.payloads
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_post_put_response(response, "POST")

        if not result["success"]:
            self._failure(response)

    def _validate_images(self, serial_numbers):
        """
        Validate the image staged to the switch(es)
        """
        if len(serial_numbers) == 0:
            return
        path = self.endpoints["image_validate"]["path"]
        verb = self.endpoints["image_validate"]["verb"]
        payload = {}
        payload["serialNumbers"] = serial_numbers
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_post_put_response(response, "POST")

        if not result["success"]:
            self._failure(response)

    def _stage_images(self, serial_numbers):
        """
        Stage the images to the switch(es)
        """
        # bootflash = DcnmBootflashInfo(self.module)
        # bootflash.serial_number = self.switch_details.serial_number
        # bootflash.refresh()
        if len(serial_numbers) == 0:
            return
        path = self.endpoints["image_stage"]["path"]
        verb = self.endpoints["image_stage"]["verb"]
        payload = {}
        payload["serialNumbers"] = serial_numbers
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_post_put_response(response, "POST")

        if not result["success"]:
            self._failure(response)

    def _upgrade_images(self, serial_numbers):
        """
        Upgrade the switch(es) to the currently-staged image
        """
        if len(serial_numbers) == 0:
            return
        path = self.endpoints["image_upgrade"]["path"]
        verb = self.endpoints["image_upgrade"]["verb"]
        payload = {}
        payload["serialNumbers"] = serial_numbers
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_post_put_response(response, "POST")

        if not result["success"]:
            self._failure(response)

    def handle_image_upgrades(self):
        """
        Update the switch policy if it has changed.
        Stage the image if requested.
        Upgrade the image if requested.

        Caller: main()
        """
        self.build_policy_attach_payload()
        self.send_policy_attach_payload()
        stage_serial_numbers = []
        upgrade_serial_numbers = []
        for switch in self.diff_create:
            self.switch_details.ip_address = switch.get('ip_address')
            if switch.get('stage') is not False:
                stage_serial_numbers.append(self.switch_details.serial_number)
            if switch.get('upgrade') is not False:
                upgrade_serial_numbers.append(self.switch_details.serial_number)
        self._stage_images(stage_serial_numbers)
        self._upgrade_images(upgrade_serial_numbers)

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



class DcnmSwitchDetails(DcnmImageUpgradeCommon):
    """
    Retrieve switch details from NDFC and provide property accessors
    for the switch attributes.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmSwitchDetails(module)
    instance.ip_address = 10.1.1.1
    fabric_name = instance.fabric_name
    serial_number = instance.serial_number
    etc...

    Switch details are retrieved on instantiation of this class.
    Switch details can be refreshed by calling instance.refresh().

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["ip_address"] = None

    def refresh(self):
        """
        Caller: __init__()

        Refresh switch_details with current switch details from NDFC
        """
        path = self.endpoints["switches_info"]["path"]
        verb = self.endpoints["switches_info"]["verb"]
        response = dcnm_send(self.module, verb, path)
        result = self._handle_get_response(response)
        if not result["success"]:
            msg = "Unable to retrieve switch information from NDFC"
            self.module.fail_json(msg=msg)

        data = response.get("DATA")
        self.data = {}
        for switch in data:
            self.data[switch["ipAddress"]] = switch

    def _get(self, item):
        if self.ip_address is None:
            msg = f"{self.__class__.__name__}: set instance.ip_address "
            msg += f"before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data[self.ip_address].get(item)

    @property
    def ip_address(self):
        """
        Set the ip_address of the switch to query.
        
        This needs to be set before accessing this class's properties.
        """
        return self.properties.get("ip_address")
    @ip_address.setter
    def ip_address(self, value):
        self.properties["ip_address"] = value

    @property
    def fabric_name(self):
        """
        Return the fabricName of the switch with ip_address, if it exists.
        Return None otherwise
        """
        return self._get("fabricName")

    @property
    def hostname(self):
        """
        Return the hostName of the switch with ip_address, if it exists.
        Return None otherwise
        """
        return self._get("hostName")

    @property
    def logical_name(self):
        """
        Return the logicalName of the switch with ip_address, if it exists.
        Return None otherwise
        """
        return self._get("logicalName")

    @property
    def model(self):
        """
        Return the model of the switch with ip_address, if it exists.
        Return None otherwise
        """
        return self._get("model")

    @property
    def platform(self):
        """
        Return the platform of the switch with ip_address, if it exists.
        Return None otherwise
        """
        model = self._get("model")
        if model is None:
            return None
        return model.split("-")[0]

    @property
    def role(self):
        """
        Return the switchRole of the switch with ip_address, if it exists.
        Return None otherwise
        """
        return self._get("switchRole")
    
    @property
    def serial_number(self):
        """
        Return the serialNumber of the switch with ip_address, if it exists.
        Return None otherwise
        """
        return self._get("serialNumber")

class DcnmImagePolicies(DcnmImageUpgradeCommon):
    """
    Retrieve image policy details from NDFC and provide property accessors
    for the policy attributes.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmImagePolicies(module)
    instance.policy_name = "NR3F"
    if instance.name is None:
        print("policy NR3F does not exist on NDFC")
        exit(1)
    policy_name = instance.name
    platform = instance.platform
    epd_image_name = instance.epld_image_name
    etc...

    Policies are retrieved on instantiation of this class.
    Policies can be refreshed by calling instance.refresh().

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/policies
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["policy_name"] = None

    def refresh(self):
        """
        Refresh self.image_policies with current image policies from NDFC
        """
        path = self.endpoints["policies_info"]["path"]
        verb = self.endpoints["policies_info"]["verb"]
        response = dcnm_send(self.module, verb, path)

        result = self._handle_get_response(response)
        if not result["success"]:
            msg = "Unable to retrieve image policy information from NDFC"
            self.module.fail_json(msg=msg)

        data = response.get("DATA").get("lastOperDataObject")
        if data is None:
            msg = "Unable to retrieve image policy information from NDFC"
            self.module.fail_json(msg=msg)
        if len(data) == 0:
            msg = "NDFC has no defined image policies"
            self.module.fail_json(msg=msg)
        self.data = {}
        for policy in data:
            policy_name = policy.get("policyName")
            if not policy_name:
                msg = "Cannot parse NDFC policy information"
                self.module.fail_json(msg=msg)
            self.data[policy_name] = policy

    def _get(self, item):
        if self.policy_name is None:
            msg = f"{self.__class__.__name__}: instance.policy_name must "
            msg += f"be set before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data[self.policy_name].get(item)

    @property
    def policy_name(self):
        """
        Set the name of the policy to query.
        """
        return self.properties.get("policy_name")
    @policy_name.setter
    def policy_name(self, value):
        self.properties["policy_name"] = value

    @property
    def policy_type(self):
        """
        Return the policyType of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("policyType")

    @property
    def nxos_version(self):
        """
        Return the nxosVersion of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("nxosVersion")

    @property
    def package_name(self):
        """
        Return the packageName of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("nxosVersion")

    @property
    def name(self):
        """
        Return the name of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("policyName")

    @property
    def platform(self):
        """
        Return the platform of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("platform")

    @property
    def description(self):
        """
        Return the policyDescr of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("policyDescr")

    @property
    def platform_policies(self):
        """
        Return the platformPolicies of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("platformPolicies")

    @property
    def epld_image_name(self):
        """
        Return the epldImgName of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("epldImgName")

    @property
    def rpm_images(self):
        """
        Return the rpmimages of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("rpmimages")

    @property
    def image_name(self):
        """
        Return the imageName of the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("imageName")

    @property
    def agnostic(self):
        """
        Return the value of agnostic for the policy matching self.policy_name,
        if it exists.
        Return None otherwise
        """
        return self._get("agnostic")


class DcnmSwitchIssuDetails(DcnmImageUpgradeCommon):
    """
    Retrieve switch issu details from NDFC and provide property accessors
    for the switch attributes.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmSwitchIssuDetails(module)
    instance.ip_address = 10.1.1.1
    image_staged = instance.image_staged
    image_upgraded = instance.image_upgraded
    serial_number = instance.serial_number
    etc...

    Switch details are retrieved on instantiation of this class.
    Switch details can be refreshed by calling instance.refresh().

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches

{
    "status": "SUCCESS",
    "lastOperDataObject": [
        {
            "serialNumber": "FDO211218GC",
            "deviceName": "cvd-1312-leaf",
            "fabric": "fff",
            "version": "10.3(2)",
            "policy": "NR3F",
            "status": "In-Sync",
            "reason": "Compliance",
            "imageStaged": "Success",
            "validated": "None",
            "upgrade": "None",
            "upgGroups": "None",
            "mode": "Normal",
            "systemMode": "Normal",
            "vpcRole": null,
            "vpcPeer": null,
            "role": "leaf",
            "lastUpgAction": "Never",
            "model": "N9K-C93180YC-EX",
            "ipAddress": "172.22.150.103",
            "issuAllowed": "",
            "statusPercent": 100,
            "imageStagedPercent": 100,
            "validatedPercent": 0,
            "upgradePercent": 0,
            "modelType": 0,
            "vdcId": 0,
            "ethswitchid": 8430,
            "platform": "N9K",
            "vpc_role": null,
            "ip_address": "172.22.150.103",
            "peer": null,
            "vdc_id": -1,
            "sys_name": "cvd-1312-leaf",
            "id": 3,
            "group": "fff",
            "fcoEEnabled": false,
            "mds": false
        },
    
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["ip_address"] = None

    def refresh(self):
        """
        Caller: __init__()

        Refresh ip_address current issu details from NDFC
        """
        path = self.endpoints["issu_info"]["path"]
        verb = self.endpoints["issu_info"]["verb"]
        response = dcnm_send(self.module, verb, path)
        result = self._handle_get_response(response)
        if not result["success"]:
            msg = "Unable to retrieve switch information from NDFC"
            self.module.fail_json(msg=msg)

        data = response.get("DATA", {}).get("lastOperDataObject", [])
        self.data = {}
        for switch in data:
            self.data[switch["ipAddress"]] = switch

    def _get(self, item):
        if self.ip_address is None:
            msg = f"{self.__class__.__name__}: set instance.ip_address "
            msg += f"before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data[self.ip_address].get(item)
    
    @property
    def raw_data(self):
        """
        Return the raw data retrieved from NDFC
        """
        return self.data

    @property
    def raw_switch_data(self):
        """
        Return the raw data for switch with ip_address retrieved from NDFC
        """
        if self.ip_address is None:
            msg = f"{self.__class__.__name__}: set instance.ip_address "
            msg += f"before accessing property raw_switch_data."
            self.module.fail_json(msg=msg)
        if self.ip_address not in self.data:
            return {}
        return self.data[self.ip_address]

    @property
    def ip_address(self):
        """
        Set the ip_address of the switch to query.
        
        This needs to be set before accessing this class's properties.
        """
        return self.properties.get("ip_address")
    @ip_address.setter
    def ip_address(self, value):
        self.properties["ip_address"] = value

    @property
    def device_name(self):
        """
        Return the deviceName of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            device name, e.g. "cvd-1312-leaf"
            None
        """
        return self._get("deviceName")

    @property
    def eth_switch_id(self):
        """
        Return the ethswitchid of the switch with
        ip_address, if it exists.
        Return None otherwise

        Possible values:
            integer
            None
        """
        return self._get("ethswitchid")

    @property
    def fabric(self):
        """
        Return the fabric of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            fabric name, e.g. "myfabric"
            None
        """
        return self._get("fabric")



    @property
    def fcoe_enabled(self):
        """
        Return whether FCOE is enabled on the switch with
        ip_address, if it exists.
        Return None otherwise

        Possible values:
            boolean (true/false)
            None
        """
        return self.make_boolean(self._get("fcoEEnabled"))

    @property
    def group(self):
        """
        Return the group of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            group name, e.g. "mygroup"
            None
        """
        return self._get("group")

    @property
    # id is a python keyword, so we can't use it as a property name
    # so we use switch_id instead
    def switch_id(self):
        """
        Return the switch ID of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer
            None
        """
        return self._get("id")

    @property
    def image_staged(self):
        """
        Return the imageStaged of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Success
            None
        """
        return self._get("imageStaged")


    @property
    def image_staged_percent(self):
        """
        Return the imageStagedPercent of the switch with
        ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer in range 0-100
            None
        """
        return self._get("imageStagedPercent")

    @property
    def issu_allowed(self):
        """
        Return the issuAllowed value of the switch with
        ip_address, if it exists.
        Return None otherwise

        Possible values:
            ?? TODO:3 check this
            ""
            None
        """
        return self._get("issuAllowed")

    @property
    def last_upg_action(self):
        """
        Return the last upgrade action performed on the switch
        with ip_address, if it exists.
        Return None otherwise

        Possible values:
            ?? TODO:3 check this
            Never
            None
        """
        return self._get("lastUpgAction")

    @property
    def mds(self):
        """
        Return whether the switch with ip_address is an MSD, if it exists.
        Return None otherwise

        Possible values:
            Boolean (True or False)
            None
        """
        return self.make_boolean(self._get("mds"))

    @property
    def mode(self):
        """
        Return the ISSU mode of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            "Normal"
            None
        """
        return self._get("mode")

    @property
    def model(self):
        """
        Return the model of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            model number e.g. "N9K-C93180YC-EX"
            None
        """
        return self._get("model")


    @property
    def model_type(self):
        """
        Return the model type of the switch with
        ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer
            None
        """
        return self._get("modelType")

    @property
    def peer(self):
        """
        Return the peer of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            ?? TODO:3 check this
            null
            None
        """
        return self._get("peer")

    @property
    def platform(self):
        """
        Return the platform of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            platform, e.g. "N9K"
            None
        """
        return self._get("platform")

    @property
    def policy(self):
        """
        Return the policy attached to the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            policy name, e.g. "NR3F"
            None
        """
        return self._get("policy")

    @property
    def reason(self):
        """
        Return the reason (?) of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Compliance
            Validate
            Upgrade
            None
        """
        return self._get("reason")

    @property
    def role(self):
        """
        Return the role of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            switch role, e.g. "leaf"
            None
        """
        return self._get("role")
    
    @property
    def serial_number(self):
        """
        Return the serialNumber of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            switch serial number, e.g. "AB1234567CD"
            None
        """
        return self._get("serialNumber")

    @property
    def status(self):
        """
        Return the sync status of the switch with ip_address, if it exists.
        Return None otherwise

        Details: The sync status is the status of the switch with respect
        to the image policy.  If the switch is in sync with the image policy,
        the status is "In-Sync".  If the switch is out of sync with the image
        policy, the status is "Out-Of-Sync".

        Possible values:
            "In-Sync"
            "Out-Of-Sync"
            None
        """
        return self._get("status")



    @property
    def status_percent(self):
        """
        Return the upgrade (TODO:3 verify this) percentage completion
        of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer in range 0-100
            None
        """
        return self._get("statusPercent")

    @property
    def sys_name(self):
        """
        Return the system name of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            system name, e.g. "cvd-1312-leaf"
            None
        """
        return self._get("sys_name")

    @property
    def system_mode(self):
        """
        Return the system mode of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            "Maintenance" (TODO:3 verify this)
            "Normal"
            None
        """
        return self._get("systemMode")

    @property
    def upgrade(self):
        """
        Return the upgrade status of the switch with ip_address,
        if it exists.
        Return None otherwise

        Possible values:
            Success
            In-Progress
            None
        """
        return self._get("upgrade")

    @property
    def upg_groups(self):
        """
        Return the upgGroups (upgrade groups) of the switch with ip_address,
        if it exists.
        Return None otherwise

        Possible values:
            upgrade group to which the switch belongs e.g. "LEAFS"
            None
        """
        return self._get("upgGroups")

    @property
    def upgrade_percent(self):
        """
        Return the upgrade percent complete of the switch
        with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer in range 0-100
            None
        """
        return self._get("upgradePercent")

    @property
    def validated(self):
        """
        Return the validation status of the switch with ip_address,
        if it exists.
        Return None otherwise

        Possible values:
            Failure (TODO:3 verify this)
            Success
            None
        """
        return self._get("validated")

    @property
    def validated_percent(self):
        """
        Return the validation percent complete of the switch
        with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer in range 0-100
            None
        """
        return self._get("validatedPercent")


    @property
    def vdc_id(self):
        """
        Return the vdcId of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer
            None
        """
        return self._get("vdcId")

    @property
    def vdc_id2(self):
        """
        Return the vdc_id of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            Integer (negative values are valid)
            None
        """
        return self._get("vdc_id")

    @property
    def version(self):
        """
        Return the version of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            version, e.g. "10.3(2)"
            None
        """
        return self._get("version")

    @property
    def vpc_peer(self):
        """
        Return the vpcPeer of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            vpc peer e.g.: 10.1.1.1
            None
        """
        return self._get("vpcPeer")

    @property
    def vpc_role(self):
        """
        Return the vpcRole of the switch with ip_address, if it exists.
        Return None otherwise

        Possible values:
            vpc role e.g.:
                "primary"
                "secondary"
                "none"
                "none established" (TODO:3 verify this)
                "primary, operational secondary" (TODO:3 verify this)
            None
        """
        return self._get("vpcRole")

def main():
    """main entry point for module execution"""

    element_spec = dict(
        config=dict(required=False, type="dict"),
        state=dict(default="merged", choices=["merged"]),
    )

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)
    dcnm_module = DcnmImageUpgrade(module)
    dcnm_module.validate_input()
    dcnm_module.get_have()
    dcnm_module.get_want()

    if module.params["state"] == "merged":
        dcnm_module.get_diff_merge()

    if dcnm_module.diff_create:
        dcnm_module.result["changed"] = True
    else:
        module.exit_json(**dcnm_module.result)

    if module.check_mode:
        dcnm_module.result["changed"] = False
        module.exit_json(**dcnm_module.result)

    if dcnm_module.diff_create:
        dcnm_module.handle_image_upgrades()

    module.exit_json(**dcnm_module.result)

class DcnmImageStageInfo(DcnmImageUpgradeCommon):
    """
    This uses an unpublished endpoint, so let's not use it for now.

    We were going to use this to get free space on the switch bootflash
    but hopefully stage-image will do that for us.

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/stage-info?serialNumber=FDO211218HH

    Response:
    [{
        "serialNumber": "FDO211218HH",
        "deviceName": "cvd-1313-leaf",
        "primary": "49013579776",
        "secodnory": "N/A",
        "requiredSpace": 0,
        "stagingFiles": [{
            "fileName": "nxos64-cs.10.3.2.F.bin",
            "size": "0"
        }]
    }]
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["serial_number"] = None

class DcnmBootflashInfo(DcnmImageUpgradeCommon):
    """
    We may not need this if stage-image does the checking of bootflash space
    for us and returns a reasonable error message...

    Retrieve bootflash information for a switch from NDFC and provide
    property accessors for the following:

        - primary_total_space (bootFlashSpaceMap["bootflash:"]["totalSpace"])
        - primary_free_space (bootFlashSpaceMap["bootflash:"]["freeSpace"])
        - primary_used_space (bootFlashSpaceMap["bootflash:"]["usedSpace"])
        TODO:2 add support for secondary bootflash when we find a switch with two supervisors

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmBootflashInfo(module)
    instance.serial_number = "AB222222CD"
    instance.refresh()
    primary_free_space = instance.primary_free_space
    secondary_free_space = instance.secondary_free_space
    etc...

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imagemgnt/bootFlash/bootflash-info?serialNumber=<serial_number>

    {
        "requiredSpace": "0 MB",
        "partitions": [
            "bootflash:"
        ],
        "bootFlashSpaceMap": {
            "bootflash:": {
                "deviceName": "cvd-1313-leaf",
                "serialNumber": "FDO211218HH",
                "ipAddr": " 172.22.150.104",
                "name": "bootflash:",
                "totalSpace": 53586325504,
                "freeSpace": 49013579776,
                "usedSpace": 4572745728,
                "bootflash_type": "active"
            }
        },
        "bootFlashDataMap": {
            "bootflash:": [
                {
                    "deviceName": "cvd-1313-leaf",
                    "serialNumber": "FDO211218HH",
                    "ipAddr": " 172.22.150.104",
                    "fileName": ".rpmstore/",
                    "size": "0",
                    "filePath": "bootflash:.rpmstore/",
                    "bootflash_type": "active",
                    "date": "May 24 21:44:08 2023",
                    "name": "bootflash:"
                },
            ]
        }
    }    
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["serial_number"] = None

    def refresh(self):
        """
        Refresh self.stage_info with current image staging state from NDFC
        """
        if self.properties["serial_number"] is None:
            msg = f"{self.__class__.__name__}: set instance.serial_number "
            msg += f"before calling refresh()."
            self.module.fail_json(msg=msg)

        path = f"{self.endpoints['bootflash_info']['path']}?serialNumber="
        path += f"{self.serial_number}"
        verb = self.endpoints["bootflash_info"]["verb"]
        response = dcnm_send(self.module, verb, path)

        result = self._handle_get_response(response)
        if not result["success"]:
            msg = "Unable to retrieve image staging information from NDFC"
            self.module.fail_json(msg=msg)

        data = response.get("DATA").get("bootFlashSpaceMap")
        if data is None:
            msg = "Unable to retrieve bootflash information from NDFC"
            self.module.fail_json(msg=msg)
        self.data = {}
        for flash_device in data.keys():
            if flash_device == "bootflash:":
                self.data["primary_total_space"] = data[flash_device]["totalSpace"]
                self.data["primary_free_space"] = data[flash_device]["freeSpace"]
                self.data["primary_used_space"] = data[flash_device]["usedSpace"]
            if flash_device == "remote-bootflash:":
                self.data["secondary_total_space"] = data[flash_device]["totalSpace"]
                self.data["secondary_free_space"] = data[flash_device]["freeSpace"]
                self.data["secondary_used_space"] = data[flash_device]["usedSpace"]


    def _get(self, item):
        if self.policy_name is None:
            msg = f"{self.__class__.__name__}: instance.policy_name must "
            msg += f"be set before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data[self.policy_name].get(item)

    @property
    def serial_number(self):
        """
        Set the serial_number of the switch to query.
        """
        return self.properties.get("serial_number")
    @serial_number.setter
    def serial_number(self, value):
        self.properties["serial_number"] = value



if __name__ == "__main__":
    main()
