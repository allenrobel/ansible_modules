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
from time import sleep

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import (
    dcnm_send, dcnm_version_supported, validate_list_of_dicts)

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
        self.endpoint_api_v1 = "/appcenter/cisco/ndfc/api/v1"
        self.endpoint_bootflash = (
            f"{self.endpoint_api_v1}/imagemanagement/rest/imagemgnt/bootFlash"
        )
        self.endpoint_image_management = f"{self.endpoint_api_v1}/imagemanagement"
        self.endpoint_feature_manager = f"{self.endpoint_api_v1}/fm"
        self.endpoint_lan_fabric = f"{self.endpoint_api_v1}/lan-fabric"

        self.endpoint_staging_management = (
            f"{self.endpoint_image_management}/rest/stagingmanagement"
        )
        self.endpoint_image_upgrade = (
            f"{self.endpoint_image_management}/rest/imageupgrade"
        )
        self.endpoint_package_mgnt = (
            f"{self.endpoint_image_management}/rest/packagemgnt"
        )
        self.endpoint_policy_mgnt = f"{self.endpoint_image_management}/rest/policymgnt"
        self.endpoints = {}
        self.endpoints["bootflash_info"] = {}
        self.endpoints["install_options"] = {}
        self.endpoints["image_stage"] = {}
        self.endpoints["image_upgrade"] = {}
        self.endpoints["image_validate"] = {}
        self.endpoints["issu_info"] = {}
        self.endpoints["ndfc_version"] = {}
        self.endpoints["policies_attached_info"] = {}
        self.endpoints["policies_info"] = {}
        self.endpoints["policy_attach"] = {}
        self.endpoints["policy_create"] = {}
        self.endpoints["policy_detach"] = {}
        self.endpoints["policy_info"] = {}
        self.endpoints["stage_info"] = {}
        self.endpoints["switches_info"] = {}

        self.endpoints["bootflash_info"][
            "path"
        ] = f"{self.endpoint_bootflash}/bootflash-info"
        self.endpoints["bootflash_info"]["verb"] = "GET"

        self.endpoints["install_options"][
            "path"
        ] = f"{self.endpoint_image_upgrade}/install-options"
        self.endpoints["install_options"]["verb"] = "POST"

        self.endpoints["image_stage"][
            "path"
        ] = f"{self.endpoint_staging_management}/stage-image"
        self.endpoints["image_stage"]["verb"] = "POST"

        self.endpoints["image_upgrade"][
            "path"
        ] = f"{self.endpoint_image_upgrade}/upgrade-image"
        self.endpoints["image_upgrade"]["verb"] = "POST"

        self.endpoints["image_validate"][
            "path"
        ] = f"{self.endpoint_staging_management}/validate-image"
        self.endpoints["image_validate"]["verb"] = "POST"

        self.endpoints["issu_info"]["path"] = f"{self.endpoint_package_mgnt}/issu"
        self.endpoints["issu_info"]["verb"] = "GET"

        self.endpoints["ndfc_version"][
            "path"
        ] = f"{self.endpoint_feature_manager}/about/version"
        self.endpoints["ndfc_version"]["verb"] = "GET"

        self.endpoints["policies_attached_info"][
            "path"
        ] = f"{self.endpoint_policy_mgnt}/all-attached-policies"
        self.endpoints["policies_attached_info"]["verb"] = "GET"

        self.endpoints["policies_info"][
            "path"
        ] = f"{self.endpoint_policy_mgnt}/policies"
        self.endpoints["policies_info"]["verb"] = "GET"

        self.endpoints["policy_attach"][
            "path"
        ] = f"{self.endpoint_policy_mgnt}/attach-policy"
        self.endpoints["policy_attach"]["verb"] = "POST"

        self.endpoints["policy_create"][
            "path"
        ] = f"{self.endpoint_policy_mgnt}/platform-policy"
        self.endpoints["policy_create"]["verb"] = "POST"

        self.endpoints["policy_detach"][
            "path"
        ] = f"{self.endpoint_policy_mgnt}/detach-policy"
        self.endpoints["policy_detach"]["verb"] = "DELETE"

        # Replace __POLICY_NAME__ with the policy_name to query
        # e.g. path.replace("__POLICY_NAME__", "NR1F")
        self.endpoints["policy_info"][
            "path"
        ] = f"{self.endpoint_policy_mgnt}/image-policy/__POLICY_NAME__"
        self.endpoints["policy_info"]["verb"] = "GET"

        self.endpoints["stage_info"][
            "path"
        ] = f"{self.endpoint_staging_management}/stage-info"
        self.endpoints["stage_info"]["verb"] = "GET"

        self.endpoints["switches_info"][
            "path"
        ] = f"{self.endpoint_lan_fabric}/rest/inventory/allswitches"
        self.endpoints["switches_info"]["verb"] = "GET"

    def _handle_response(self, response, verb):
        if verb == "GET":
            return self._handle_get_response(response)
        if verb in {"POST", "PUT", "DELETE"}:
            return self._handle_post_put_delete_response(response)
        return self._handle_unknown_request_verbs(response, verb)

    def _handle_unknown_request_verbs(self, response, verb):
        msg=f"Unknown request verb ({verb}) in _handle_response()."
        self.module.fail_json(msg=msg)

    def _handle_get_response(self, response):
        """
        Caller:
            - self._handle_response()
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

    def _handle_post_put_delete_response(self, response):
        """
        Caller:
            - self.self._handle_response()

        Handle POST, PUT responses from NDFC.

        Returns: dict() with the following keys:
        - changed:
            - True if changes were made to NDFC
            - False otherwise
        - success:
            - False if RETURN_CODE != 200 or MESSAGE != "OK"
            - True otherwise
        """
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
        by setting __init__().debug to False
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
            msg = +f"got {type(self.config).__name__}"
            self.module.fail_json(msg=msg)

        self.check_mode = False
        self.validated = []
        self.have_create = []
        self.want_create = []
        self.diff_create = []
        self.diff_save = {}
        self.query = []
        self.result = dict(changed=False, diff=[], response=[])

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
        self.have = DcnmSwitchIssuDetailsByIpAddress(self.module)

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
                if (
                    idempotent_want["policy_changed"] is False
                    and idempotent_want["stage"] is False
                    and idempotent_want["upgrade"] is False
                ):
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
        params_spec.update(policy=dict(required=True, type="str"))
        params_spec.update(upgrade=dict(required=False, type="bool", default=True))
        params_spec.update(stage=dict(required=False, type="bool", default=True))
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
        for switch in self.switch_configs:
            if not switch.get("ip_address"):
                msg = "playbook is missing ip_address for at least one switch"
                self.module.fail_json(msg)
            if not switch.get("policy"):
                msg = "playbook is missing image policy for switch "
                msg += f"{switch.get('ip_address')} "
                msg = "and global image policy is not defined"
                self.module.fail_json(msg)
            if switch.get("stage") is None:
                switch["stage"] = self.defaults["stage"]
            if switch.get("upgrade") is None:
                switch["upgrade"] = self.defaults["upgrade"]

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
            if switch.get("policy_changed") is False:
                continue
            self.switch_details.ip_address = switch.get("ip_address")
            self.image_policies.policy_name = switch.get("policy")

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
        result = self._handle_response(response, verb)

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
        payload["nonDisruptive"] = True
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_response(response, verb)

        if not result["success"]:
            self._failure(response)

    def _stage_images(self, serial_numbers):
        """
        Initiate image staging to the switch(es) associated with serial_numbers
        """
        stage = DcnmImageStage(self.module)
        stage.serial_numbers = serial_numbers
        stage.commit()

    def _upgrade_images(self, devices):
        """
        1. Verify image validation status
        2. Upgrade the switch(es) to the currently-validated image

        Endpoint:
        /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imageupgrade/upgrade-image

        upgrade-image request body:

            {
                "devices": [
                    {
                        "serialNumber": "FDO2338082P",
                        "policyName": "MyPolicy"
                    }
                ],
                "issu": true,
                "issuUpgradeOptions1": {
                    "nonDisruptive": true,
                    "forceNonDisruptive": false,
                    "disruptive": false
                },
                "epldUpgrade": false,
                "epldOptions": {
                    "moduleNumber": "ALL",
                    "golden": false
                },
                "pacakgeInstall": true,
                "pacakgeUnInstall": false,
                "reboot": false,
                "rebootOptions": false
            }

        """
        if len(devices) == 0:
            return
        install_options = DcnmImageInstallOptions(self.module)
        for device in devices:
            install_options.serial_number = device["serial_number"]
            install_options.policy_name = device["policy_name"]
            install_options.refresh()
            if install_options.status not in ["Success", "Skipped"]:
                msg = f"Got install options status {install_options.status} "
                msg += f"for device {device['serial_number']} "
                msg += f"with ip_address {device['ip_address']}."
                self.module.fail_json(msg=msg)

        # path = self.endpoints["image_upgrade"]["path"]
        # verb = self.endpoints["image_upgrade"]["verb"]
        # payload = {}
        # payload["serialNumbers"] = serial_numbers
        # response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        # result = self._handle_response(response, verb)

        # if not result["success"]:
        #     self._failure(response)

    def handle_image_upgrades(self):
        """
        Update the switch policy if it has changed.
        Stage the image if requested.
        Upgrade the image if requested.

        Caller: main()
        """
        self.build_policy_attach_payload()
        self.send_policy_attach_payload()
        stage_devices = []
        upgrade_devices = []
        for switch in self.diff_create:
            self.switch_details.ip_address = switch.get("ip_address")
            device = {}
            device["serial_number"] = self.switch_details.serial_number
            self.have.ip_address = self.switch_details.ip_address
            device["policy_name"] = self.have.policy
            device["ip_address"] = self.switch_details.ip_address
            if switch.get("stage") is not False:
                stage_devices.append(device)
            if switch.get("upgrade") is not False:
                upgrade_devices.append(device)

        self._stage_images(stage_devices)
        self._upgrade_images(upgrade_devices)

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
        self.properties["ndfc_response"] = None
        self.properties["ndfc_result"] = None

    def refresh(self):
        """
        Caller: __init__()

        Refresh switch_details with current switch details from NDFC
        """
        path = self.endpoints["switches_info"]["path"]
        verb = self.endpoints["switches_info"]["verb"]
        self.properties["ndfc_response"] = dcnm_send(self.module, verb, path)
        self.properties["ndfc_result"] = self._handle_response(self.ndfc_response, verb)
        if not self.ndfc_result["success"]:
            msg = "Unable to retrieve switch information from NDFC"
            self.module.fail_json(msg=msg)

        data = self.ndfc_response.get("DATA")
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

        NOTES:
        1. This is None for 12.1.2e
        2. Better to use logical_name which is populated in both 12.1.2e and 12.1.3b
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
    def ndfc_response(self):
        """
        Return the raw response from the GET request.
        Return None otherwise
        """
        return self.properties["ndfc_response"]

    @property
    def ndfc_result(self):
        """
        Return the raw result of the GET request.
        Return None otherwise
        """
        return self.properties["ndfc_result"]

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


class DcnmImageInstallOptions(DcnmImageUpgradeCommon):
    """
    Retrieve install-options details for ONE switch from NDFC and
    provide property accessors for the policy attributes.

    Caveats:
        -   This retrieves for a SINGLE switch only.
        -   Set serial_number and policy_name and call refresh() for
            each switch separately.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmImageInstallOptions(module)
    # Mandatory
    instance.policy_name = "NR3F"
    instance.serial_number = "FDO211218GC"
    # Optional
    instance.epld = True
    instance.package_install = True
    instance.issu = True
    # Retrieve install-options details from NDFC
    instance.refresh()
    if instance.device_name is None:
        print("Cannot retrieve policy/serial_number combination from NDFC")
        exit(1)
    status = instance.status
    platform = instance.platform
    etc...

    install-options are retrieved by calling instance.refresh().

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imageupgrade/install-options
    Request body:
    {
        "devices": [
            {
                "serialNumber": "FDO211218HH",
                "policyName": "NR1F"
            },
            {
                "serialNumber": "FDO211218GC",
                "policyName": "NR3F"
            }
        ],
        "issu": true,
        "epld": false,
        "packageInstall": false
    }
    Response body:
        install-options response body:
        TODO:1 handle this in a class DcnmInstallOptions()
            {
                "compatibilityStatusList": [
                    {
                        "deviceName": "cvd-1313-leaf",
                        "ipAddress": "172.22.150.104",
                        "policyName": "NR1F",
                        "platform": "N9K/N3K",
                        "version": "10.3.2",
                        "osType": "64bit",
                        "status": "Success",
                        "installOption": "non-disruptive",
                        "compDisp": "[show install all impact nxos bootflash:nxos64-cs.10.3.2.F.bin non-disruptive cli output]",
                        "versionCheck": "cli output elided...",
                        "preIssuLink": "Not Applicable",
                        "repStatus": "skipped",
                        "timestamp": "NA"
                    },
                    {
                        "deviceName": "cvd-1313-leaf",
                        "ipAddress": "172.22.150.104",
                        "policyName": "NR1F",
                        "platform": "N9K/N3K",
                        "version": "10.3.2",
                        "osType": "64bit",
                        "status": "Success",
                        "installOption": "non-disruptive",
                        "compDisp": "[cli output for show install all impact nxos bootflash:nxos.10.3.2.bin]",
                        "versionCheck": "cli output elided...",
                        "preIssuLink": "Not Applicable",
                        "repStatus": "skipped",
                        "timestamp": "NA"
                    }
                ],
                "epldModules": null,
                "installPacakges": null,
                "errMessage": ""
            }

    """

    def __init__(self, module):
        super().__init__(module)
        self._init_properties()

    def _init_properties(self):
        self.properties = {}
        self.properties["policy_name"] = None
        self.properties["serial_number"] = None
        self.properties["issu"] = True
        self.properties["epld"] = False
        self.properties["package_install"] = False
        self.response = None
        self.result = None
        self.data = None

    def refresh(self):
        """
        Refresh self.data with current install-options from NDFC
        """
        if self.policy_name is None:
            msg = f"{self.__class__.__name__}: instance.policy_name must "
            msg += f"be set before calling refresh()"
            self.module.fail_json(msg=msg)
        if self.serial_number is None:
            msg = f"{self.__class__.__name__}: instance.serial_number must "
            msg += f"be set before calling refresh()"
            self.module.fail_json(msg=msg)

        path = self.endpoints["install_options"]["path"]
        verb = self.endpoints["install_options"]["verb"]
        self._build_payload()
        self.response = dcnm_send(
            self.module, verb, path, data=json.dumps(self.payload)
        )
        self.result = self._handle_response(self.response, verb)
        if not self.result["success"]:
            msg = "Unable to retrieve install-options information from NDFC"
            self.module.fail_json(msg=msg)

        data = self.response.get("DATA").get("compatibilityStatusList")
        if data is None:
            msg = "Unable to retrieve install-options information from NDFC"
            self.module.fail_json(msg=msg)
        if len(data) == 0:
            msg = "NDFC has no defined install-options"
            self.module.fail_json(msg=msg)
        self.data = data[0]

    def _build_payload(self):
        """
        {
            "devices": [
                {
                    "serialNumber": "FDO211218HH",
                    "policyName": "NR1F"
                }
            ],
            "issu": true,
            "epld": false,
            "packageInstall": false
        }
        """
        self.payload = {}
        self.payload["devices"] = []
        devices = {}
        devices["serialNumber"] = self.serial_number
        devices["policyName"] = self.policy_name
        self.payload["devices"].append(devices)
        self.payload["issu"] = self.issu
        self.payload["epld"] = self.epld
        self.payload["packageInstall"] = self.package_install

    def _get(self, item):
        return self.data.get(item)

    # Mandatory properties
    @property
    def policy_name(self):
        """
        Set the policy_name of the policy to query.
        """
        return self.properties.get("policy_name")

    @policy_name.setter
    def policy_name(self, value):
        self.properties["policy_name"] = value

    @property
    def serial_number(self):
        """
        Set the serial_number of the device to query.
        """
        return self.properties.get("serial_number")

    @serial_number.setter
    def serial_number(self, value):
        self.properties["serial_number"] = value

    # Optional properties
    @property
    def issu(self):
        """
        Enable (True) or disable (False) issu compatibility check.
        Valid values:
            True - Enable issu compatibility check
            False - Disable issu compatibility check
        Default: True
        """
        return self.properties.get("issu")

    @issu.setter
    def issu(self, value):
        self.properties["issu"] = value

    @property
    def epld(self):
        """
        Enable (True) or disable (False) epld compatibility check.

        Valid values:
            True - Enable epld compatibility check
            False - Disable epld compatibility check
        Default: False
        """
        return self.properties.get("epld")

    @epld.setter
    def epld(self, value):
        self.properties["epld"] = value

    @property
    def package_install(self):
        """
        Enable (True) or disable (False) package_install compatibility check.
        Valid values:
            True - Enable package_install compatibility check
            False - Disable package_install compatibility check
        Default: False
        """
        return self.properties.get("package_install")

    @package_install.setter
    def package_install(self, value):
        self.properties["package_install"] = value

    # Retrievable properties
    @property
    def comp_disp(self):
        """
        Return the compDisp (CLI output from show install all status)
        of the install-options response, if it exists.
        Return None otherwise
        """
        return self._get("compDisp")

    @property
    def device_name(self):
        """
        Return the deviceName of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("deviceName")

    @property
    def install_option(self):
        """
        Return the installOption of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("installOption")

    @property
    def ip_address(self):
        """
        Return the ipAddress of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("ipAddress")

    @property
    def os_type(self):
        """
        Return the osType of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("osType")

    @property
    def platform(self):
        """
        Return the platform of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("platform")

    @property
    def pre_issu_link(self):
        """
        Return the preIssuLink of the install-options response, if it exists.
        Return None otherwise
        """
        return self._get("preIssuLink")

    @property
    def raw_data(self):
        """
        Return the raw data of the install-options response, if it exists.
        """
        return self.data

    @property
    def raw_response(self):
        """
        Return the raw response, if it exists.
        """
        return self.response

    @property
    def rep_status(self):
        """
        Return the repStatus of the install-options response, if it exists.
        Return None otherwise
        """
        return self._get("repStatus")

    @property
    def status(self):
        """
        Return the status of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("status")

    @property
    def timestamp(self):
        """
        Return the timestamp of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("timestamp")

    @property
    def version(self):
        """
        Return the version of the install-options response,
        if it exists.
        Return None otherwise
        """
        return self._get("version")

    @property
    def version_check(self):
        """
        Return the versionCheck (version check CLI output)
        of the install-options response, if it exists.
        Return None otherwise
        """
        return self._get("versionCheck")


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

        result = self._handle_response(response, verb)
        self.log_msg(f"TODO: DcnmImagePolicies.refresh() result: {result}")
        if not result["success"]:
            msg = "Unable to retrieve image policy information from NDFC"
            self.module.fail_json(msg=msg)

        data = response.get("DATA").get("lastOperDataObject")
        self.log_msg(f"TODO: DcnmImagePolicies.refresh() data: {data}")
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

        This must be set prior to accessing any other properties
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

    Usage: See subclasses.

    Switch details are retrieved on instantiation of this class.
    Switch details can be refreshed by calling instance.refresh().

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches

    Response body:
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
            {etc...}
        ]

    """

    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["ndfc_response"] = None
        self.properties["ndfc_result"] = None
        # used in subclasses to determine if any actions are in progress
        # property actions_in_progress return True if so, False otherwise
        self.properties["action_keys"] = set()
        self.properties["action_keys"].add("imageStaged")
        self.properties["action_keys"].add("upgrade")
        self.properties["action_keys"].add("validated")

    def refresh(self):
        """
        Caller: __init__()

        Refresh current issu details from NDFC
        """
        path = self.endpoints["issu_info"]["path"]
        verb = self.endpoints["issu_info"]["verb"]
        self.properties["ndfc_response"] = dcnm_send(self.module, verb, path)
        self.properties["ndfc_result"] = self._handle_response(self.ndfc_response, verb)
        if not self.ndfc_result["success"]:
            msg = "Unable to retrieve switch information from NDFC"
            self.module.fail_json(msg=msg)
        self.data = self.ndfc_response.get("DATA", {}).get("lastOperDataObject", [])

    @property
    def actions_in_progress(self):
        """
        Return True if any actions are in progress
        Return False otherwise

        overwriten in subclasses
        """
        pass

    def _get(self, item):
        """
        overwritten in subclasses
        """
        pass

    @property
    def ndfc_response(self):
        """
        Return the raw response from the GET request.
        Return None otherwise
        """
        return self.properties["ndfc_response"]

    @property
    def ndfc_result(self):
        """
        Return the raw result of the GET request.
        Return None otherwise
        """
        return self.properties["ndfc_result"]

    @property
    def raw_data(self):
        """
        Return the raw data retrieved from NDFC
        """
        return self.data

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
            Failed
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
    def ip_address(self):
        """
        Return the ipAddress of the switch, if it exists.
        Return None otherwise

        Possible values:
            switch IP address
            None
        """
        return self._get("ipAddress")

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


class DcnmSwitchIssuDetailsByIpAddress(DcnmSwitchIssuDetails):
    """
    Retrieve switch issu details from NDFC and provide property accessors
    for the switch attributes retrieved by ip address.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmSwitchIssuDetailsByIpAddress(module)
    instance.ip_address = 10.1.1.1
    image_staged = instance.image_staged
    image_upgraded = instance.image_upgraded
    serial_number = instance.serial_number
    etc...

    See DcnmSwitchIssuDetails for more details.
    """

    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        super()._init_properties()
        self.properties["ip_address"] = None

    def refresh(self):
        """
        Caller: __init__()

        Refresh ip_address current issu details from NDFC
        """
        super().refresh()
        self.data_subclass = {}
        for switch in self.data:
            self.data_subclass[switch["ipAddress"]] = switch

    def _get(self, item):
        if self.ip_address is None:
            msg = f"{self.__class__.__name__}: set instance.ip_address "
            msg += f"before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data_subclass[self.ip_address].get(item)

    @property
    def actions_in_progress(self):
        """
        Return True if any actions are in progress
        Return False otherwise
        """
        for action_key in self.properties["action_keys"]:
            if self._get(action_key) == "In-Progress":
                return True
        return False

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


class DcnmSwitchIssuDetailsBySerialNumber(DcnmSwitchIssuDetails):
    """
    Retrieve switch issu details from NDFC and provide property accessors
    for the switch attributes retrieved by serial_number.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmSwitchIssuDetailsBySerialNumber(module)
    instance.serial_number = "FDO211218GC"
    image_staged = instance.image_staged
    image_upgraded = instance.image_upgraded
    ip_address = instance.ip_address
    etc...

    See DcnmSwitchIssuDetails for more details.

    """

    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        super()._init_properties()
        self.properties["serial_number"] = None

    def refresh(self):
        """
        Caller: __init__()

        Refresh serial_number current issu details from NDFC
        """
        super().refresh()
        self.data_subclass = {}
        for switch in self.data:
            self.data_subclass[switch["serialNumber"]] = switch

    def _get(self, item):
        if self.serial_number is None:
            msg = f"{self.__class__.__name__}: set instance.serial_number "
            msg += f"before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data_subclass[self.serial_number].get(item)

    @property
    def actions_in_progress(self):
        """
        Return True if any actions are in progress
        Return False otherwise
        """
        for action_key in self.properties["action_keys"]:
            if self._get(action_key) == "In-Progress":
                return True
        return False

    @property
    def serial_number(self):
        """
        Set the serial_number of the switch to query.

        This needs to be set before accessing this class's properties.
        """
        return self.properties.get("serial_number")

    @serial_number.setter
    def serial_number(self, value):
        self.properties["serial_number"] = value


class DcnmSwitchIssuDetailsByDeviceName(DcnmSwitchIssuDetails):
    """
    Retrieve switch issu details from NDFC and provide property accessors
    for the switch attributes retrieved by device_name.

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmSwitchIssuDetailsByDeviceName(module)
    instance.device_name = "leaf_1"
    image_staged = instance.image_staged
    image_upgraded = instance.image_upgraded
    ip_address = instance.ip_address
    etc...

    See DcnmSwitchIssuDetails for more details.

    """

    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        super()._init_properties()
        self.properties["device_name"] = None

    def refresh(self):
        """
        Caller: __init__()

        Refresh device_name current issu details from NDFC
        """
        super().refresh()
        self.data_subclass = {}
        for switch in self.data:
            self.data_subclass[switch["deviceName"]] = switch

    def _get(self, item):
        if self.device_name is None:
            msg = f"{self.__class__.__name__}: set instance.device_name "
            msg += f"before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data_subclass[self.device_name].get(item)

    @property
    def actions_in_progress(self):
        """
        Return True if any actions are in progress
        Return False otherwise
        """
        for action_key in self.properties["action_keys"]:
            if self._get(action_key) == "In-Progress":
                return True
        return False

    @property
    def device_name(self):
        """
        Set the device_name of the switch to query.

        This needs to be set before accessing this class's properties.
        """
        return self.properties.get("device_name")

    @device_name.setter
    def device_name(self, value):
        self.properties["device_name"] = value


class DcnmImageStage(DcnmImageUpgradeCommon):
    """
    Endpoint:
        /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/stagingmanagement/stage-image

    Usage (where module is an instance of AnsibleModule):

    stage = DcnmImageStage(module)
    stage.serial_numbers = ["FDO211218HH", "FDO211218GC"]
    stage.commit()
    data = stage.data

    Request body (12.1.2e) (yes, serialNum is misspelled):
        {
            "sereialNum": [
                "FDO211218HH",
                "FDO211218GC"
            ]
        }
    Request body (12.1.3b):
        {
            "serialNumbers": [
                "FDO211218HH",
                "FDO211218GC"
            ]
        }

    Response:
        Unfortunately, the response does not contain consistent data.
        Would be better if all responses contained serial numbers as keys so that
        we could verify against a set() of serial numbers.  Sigh.  It is what it is.
        {
            'RETURN_CODE': 200,
            'METHOD': 'POST',
            'REQUEST_PATH': 'https: //172.22.150.244:443/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/stagingmanagement/stage-image',
            'MESSAGE': 'OK',
            'DATA': [
                {
                    'key': 'success',
                    'value': ''
                },
                {
                    'key': 'success',
                    'value': ''
                }
            ]
        }

        Response when there are no files to stage:
        [
            {
                "key": "FDO211218GC",
                "value": "No files to stage"
            },
            {
                "key": "FDO211218HH",
                "value": "No files to stage"
            }
        ]
    """

    def __init__(self, module):
        super().__init__(module)
        self.class_name = self.__class__.__name__
        self._init_properties()
        self._populate_ndfc_version()

    def _init_properties(self):
        self.properties = {}
        self.properties["serial_numbers"] = None
        self.properties["data"] = None
        self.properties["ndfc_result"] = None
        self.properties["ndfc_response"] = None
        self.properties["check_interval"] = 10  # seconds
        self.properties["check_timeout"] = 300  # seconds

    def _populate_ndfc_version(self):
        """
        Populate self.ndfc_version with the NDFC version.

        Notes:
        1.  This cannot go into DcnmImageUpgradeCommon() due to circular
            imports resulting in RecursionError
        """
        instance = DcnmNdfcVersion(self.module)
        self.ndfc_version = instance.version

    def prune_serial_numbers(self):
        """
        If the image is already staged on a switch, remove that switch's
        serial number from the list of serial numbers to stage.
        """
        issu = DcnmSwitchIssuDetailsBySerialNumber(self.module)
        for serial_number in self.serial_numbers:
            issu.serial_number = serial_number
            issu.refresh()
            if issu.image_staged == "Success":
                msg = "image already staged for "
                msg += f"{issu.serial_number} / {issu.ip_address}"
                self.log_msg(msg)
                self.serial_numbers.remove(issu.serial_number)

    def validate_serial_numbers(self):
        """
        Fail if the image_staged state for any serial_number
        is Failed.
        """
        issu = DcnmSwitchIssuDetailsBySerialNumber(self.module)
        for serial_number in self.serial_numbers:
            issu.serial_number = serial_number
            issu.refresh()
            if issu.image_staged == "Failed":
                msg = "Image staging is failing for the following switch: "
                msg += f"{issu.device_name}, {issu.ip_address}, "
                msg += f"{issu.serial_number}. Please check the switch "
                msg += "connectivity to NDFC and try again."
                self.module.fail_json(msg)

    def commit(self):
        """
        Commit the image staging request to NDFC and wait
        for the images to be staged.
        """
        if self.serial_numbers is None:
            msg = f"{self.class_name}.commit() call instance.serial_numbers "
            msg += "before calling commit()."
            self.module.fail_json(msg=msg)
        if len(self.serial_numbers) == 0:
            msg = f"{self.class_name}.commit() no serial numbers to stage."
            return
        self.prune_serial_numbers()
        self.validate_serial_numbers()
        self._wait_for_current_actions_to_complete()
        path = self.endpoints["image_stage"]["path"]
        verb = self.endpoints["image_stage"]["verb"]
        payload = {}
        if self.ndfc_version == "12.1.2e":
            payload["sereialNum"] = self.serial_numbers
        else:
            payload["serialNumbers"] = self.serial_numbers
        self.properties["ndfc_response"] = dcnm_send(
            self.module, verb, path, data=json.dumps(payload)
        )
        self.properties["ndfc_result"] = self._handle_response(self.ndfc_response, verb)
        self.log_msg(f"TODO: DcnmImageStage.commit() response: {self.ndfc_response}")
        self.log_msg(f"TODO: DcnmImageStage.commit() result: {self.ndfc_result}")
        if not self.ndfc_result["success"]:
            msg = f"{self.class_name}.commit() failed: {self.ndfc_result}. "
            msg += f"NDFC response was: {self.ndfc_response}"
            self.module.fail_json(msg=msg)
        self.properties["data"] = self.ndfc_response.get("DATA")
        self._wait_for_image_stage_to_complete()

    def _wait_for_current_actions_to_complete(self):
        """
        NDFC will not stage an image if there are any actions in progress.
        Wait for all actions to complete before staging image.
        Actions include image staging, image upgrade, and image validation.
        """
        serial_numbers = copy.deepcopy(self.serial_numbers)
        timeout = self.check_timeout
        issu = DcnmSwitchIssuDetailsBySerialNumber(self.module)
        while len(serial_numbers) > 0 and timeout > 0:
            sleep(self.check_interval)
            timeout -= self.check_interval
            for serial_number in self.serial_numbers:
                if serial_number not in serial_numbers:
                    continue
                issu.serial_number = serial_number
                issu.refresh()
                if issu.actions_in_progress is False:
                    msg = f"{self.class_name}: "
                    msg += "_wait_for_current_actions_to_complete: "
                    msg += f"{serial_number} no actions in progress. "
                    msg += f"Removing. {timeout} seconds remaining."
                    self.log_msg(msg)
                    serial_numbers.remove(serial_number)

    def _wait_for_image_stage_to_complete(self):
        """
        # Wait for image stage to complete
        """
        issu = DcnmSwitchIssuDetailsBySerialNumber(self.module)
        serial_numbers_complete = set()
        timeout = self.check_timeout
        serial_numbers_remaining = set(copy.deepcopy(self.serial_numbers))
        while serial_numbers_complete != serial_numbers_remaining and timeout > 0:
            sleep(self.check_interval)
            timeout -= self.check_interval
            msg = f"_stage_images: issu seconds remaining: {timeout} "
            msg += f"serial_numbers complete: {serial_numbers_complete} "
            msg += f"serial_numbers remaining: {serial_numbers_remaining}"
            self.log_msg(msg)
            for serial_number in self.serial_numbers:
                if serial_number in serial_numbers_complete:
                    continue
                issu.serial_number = serial_number
                issu.refresh()
                msg = f"Seconds remaining {timeout}: "
                msg += f"{issu.serial_number} / {issu.ip_address} "
                msg += f"image staged percent: {issu.image_staged_percent}"
                self.log_msg(msg)
                if issu.image_staged == "Failed":
                    msg = f"Seconds remaining {timeout}: stage image failed for "
                    msg += f"{issu.serial_number} / {issu.ip_address}"
                    self.module.fail_json(msg=msg)
                if issu.image_staged == "Success":
                    msg = f"Seconds remaining {timeout}: stage image complete for "
                    msg += f"{issu.serial_number} / {issu.ip_address}"
                    self.log_msg(msg)
                    serial_numbers_complete.add(issu.serial_number)
                if issu.image_staged == None:
                    msg = f"Seconds remaining {timeout}: stage image not stated for "
                    msg += f"{issu.serial_number} / {issu.ip_address}"
                    self.log_msg(msg)
                if issu.image_staged == "In Progress":
                    msg = f"Seconds remaining {timeout}: stage image in progress for "
                    msg += f"{issu.serial_number} / {issu.ip_address}"
                    self.log_msg(msg)

    @property
    def serial_numbers(self):
        """
        Set the serial numbers of the switches to stage.

        This must be set before calling instance.commit()
        """
        return self.properties.get("serial_numbers")

    @serial_numbers.setter
    def serial_numbers(self, value):
        if not isinstance(value, list):
            msg = f"{self.__class__.__name__}: instance.serial_numbers must "
            msg += f"be a python list of switch serial numbers."
            self.module.fail_json(msg=msg)
        self.properties["serial_numbers"] = value

    @property
    def data(self):
        """
        Return the result of the image staging request
        for serial_numbers.

        instance.serial_numbers must be set first.
        """
        return self.properties.get("data")

    @property
    def ndfc_result(self):
        """
        Return the POST result from NDFC
        """
        return self.properties.get("ndfc_result")

    @property
    def ndfc_response(self):
        """
        Return the POST response from NDFC
        """
        return self.properties.get("ndfc_response")

    @property
    def check_interval(self):
        """
        Return the stage check interval in seconds
        """
        return self.properties.get("check_interval")

    @property
    def check_timeout(self):
        """
        Return the stage check interval in seconds
        """
        return self.properties.get("check_timeout")


class DcnmNdfcVersion(DcnmImageUpgradeCommon):
    """
    Return image version information from NDFC

    NOTES:
    1.  considered using dcnm_version_supported() but it does not return
        minor release info, which is needed due to key changes between
        12.1.2e and 12.1.3b (for example)

    Endpoint:
        /appcenter/cisco/ndfc/api/v1/fm/about/version

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmNdfcVersion(module)
    if instance.version == "12.1.2e":
        do 12.1.2e stuff
    else:
        do other stuff

    Response:
        {
            "version": "12.1.2e",
            "mode": "LAN",
            "isMediaController": false,
            "dev": false,
            "isHaEnabled": false,
            "install": "EASYFABRIC",
            "uuid": "f49e6088-ad4f-4406-bef6-2419de914ff1",
            "is_upgrade_inprogress": false
        }
    """

    def __init__(self, module):
        super().__init__(module)
        self.class_name = self.__class__.__name__
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["data"] = None
        self.properties["ndfc_result"] = None
        self.properties["ndfc_response"] = None

    def refresh(self):
        """
        Refresh self.data with current version info from NDFC
        """
        path = self.endpoints["ndfc_version"]["path"]
        verb = self.endpoints["ndfc_version"]["verb"]
        self.properties["ndfc_response"] = dcnm_send(self.module, verb, path)
        self.properties["ndfc_result"] = self._handle_response(self.ndfc_response, verb)
        self.log_msg(
            f"TODO: {self.class_name}.refresh() response: {self.ndfc_response}"
        )
        self.log_msg(f"TODO: {self.class_name}.refresh() result: {self.ndfc_result}")
        if not self.ndfc_result["success"]:
            msg = f"{self.class_name}.refresh() failed: {self.ndfc_result}"
            self.module.fail_json(msg=msg)
        self.properties["data"] = self.ndfc_response.get("DATA")

    def _get(self, item):
        return self.data.get(item)

    @property
    def data(self):
        """
        Return the data retrieved from the request
        """
        return self.properties.get("data")

    @property
    def dev(self):
        """
        Return True if NDFC is a development release.
        Return False if NDFC is not a development release.
        Return None otherwise

        Possible values:
            True
            False
            None
        """
        return self.make_boolean(self._get("dev"))

    @property
    def install(self):
        """
        Return the value of install, if it exists.
        Return None otherwise

        Possible values:
            EASYFABRIC
            (probably other values)
            None
        """
        return self._get("install")

    @property
    def is_ha_enabled(self):
        """
        Return True if NDFC is a media controller.
        Return False if NDFC is not a media controller.
        Return None otherwise

        Possible values:
            True
            False
            None
        """
        return self.make_boolean(self._get("isHaEnabled"))

    @property
    def is_upgrade_inprogress(self):
        """
        Return True if an NDFC upgrade is in progress.
        Return False if an NDFC upgrade is not in progress.
        Return None otherwise

        Possible values:
            True
            False
            None
        """
        return self.make_boolean(self._get("is_upgrade_inprogress"))

    @property
    def is_media_controller(self):
        """
        Return True if NDFC is a media controller.
        Return False if NDFC is not a media controller.
        Return None otherwise

        Possible values:
            True
            False
            None
        """
        return self.make_boolean(self._get("isMediaController"))

    @property
    def ndfc_result(self):
        """
        Return the POST result from NDFC
        """
        return self.properties.get("ndfc_result")

    @property
    def ndfc_response(self):
        """
        Return the POST response from NDFC
        """
        return self.properties.get("ndfc_response")

    @property
    def mode(self):
        """
        Return the NDFC mode, if it exists.
        Return None otherwise

        Possible values:
            LAN
            None
        """
        return self._get("mode")

    @property
    def uuid(self):
        """
        Return the value of uuid, if it exists.
        Return None otherwise

        Possible values:
            uuid e.g. "f49e6088-ad4f-4406-bef6-2419de914df1"
            None
        """
        return self._get("uuid")

    @property
    def version(self):
        """
        Return the NDFC version, if it exists.
        Return None otherwise

        Possible values:
            version, e.g. "12.1.2e"
            None
        """
        return self._get("version")

    @property
    def version_major(self):
        """
        Return the NDFC major version, if it exists.
        Return None otherwise

        We are assuming semantic versioning based on:
        https://semver.org

        Possible values:
            if version is 12.1.2e, return 12
            None
        """
        return (self._get("version").split("."))[0]

    @property
    def version_minor(self):
        """
        Return the NDFC minor version, if it exists.
        Return None otherwise

        We are assuming semantic versioning based on:
        https://semver.org

        Possible values:
            if version is 12.1.2e, return 1
            None
        """
        return (self._get("version").split("."))[1]

    @property
    def version_patch(self):
        """
        Return the NDFC minor version, if it exists.
        Return None otherwise

        We are assuming semantic versioning based on:
        https://semver.org

        Possible values:
            if version is 12.1.2e, return 2e
            None
        """
        return (self._get("version").split("."))[2]


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


if __name__ == "__main__":
    main()
