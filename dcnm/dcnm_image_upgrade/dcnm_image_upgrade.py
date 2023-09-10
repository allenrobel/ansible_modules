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
        self.endpoint_image_management = "/appcenter/cisco/ndfc/api/v1/imagemanagement"
        self.endpoint_image_upgrade = f"{self.endpoint_image_management}/rest/imageupgrade"
        self.endpoint_package_mgnt = f"{self.endpoint_image_management}/rest/packagemgnt"
        self.endpoint_policy_mgnt = f"{self.endpoint_image_management}/rest/policymgnt"
        self.endpoint_lan_fabric = "/appcenter/cisco/ndfc/api/v1/lan-fabric"
        self.endpoints = {}
        self.endpoints["attach_policy"] = {}
        self.endpoints["attached_policies"] = {}
        self.endpoints["create_policy"] = {}
        self.endpoints["detach_policy"] = {}
        self.endpoints["query_all_policies"] = {}
        self.endpoints["query_all_switches"] = {}
        self.endpoints["query_one_policy"] = {}
        self.endpoints["query_issu"] = {}
        self.endpoints["upgrade_image"] = {}
        
        self.endpoints["attached_policies"]["path"] = f"{self.endpoint_policy_mgnt}/all-attached-policies"
        self.endpoints["attached_policies"]["verb"] = "GET"

        self.endpoints["attach_policy"]["path"] = f"{self.endpoint_policy_mgnt}/attach-policy"
        self.endpoints["attach_policy"]["verb"] = "POST"

        self.endpoints["create_policy"]["path"] = f"{self.endpoint_policy_mgnt}/platform-policy"
        self.endpoints["create_policy"]["verb"] = "POST"

        self.endpoints["detach_policy"]["path"] = f"{self.endpoint_policy_mgnt}/detach-policy"
        self.endpoints["detach_policy"]["verb"] = "DELETE"

        self.endpoints["attached_policies"]["path"] = f"{self.endpoint_policy_mgnt}/all-attached-policies"
        self.endpoints["attached_policies"]["verb"] = "GET"

        self.endpoints["query_all_policies"]["path"] = f"{self.endpoint_policy_mgnt}/policies"
        self.endpoints["query_all_policies"]["verb"] = "GET"

        # Replace __POLICY_NAME__ with the policy_name to query
        # e.g. path.replace("__POLICY_NAME__", "NR1F")
        self.endpoints["query_one_policy"]["path"] = f"{self.endpoint_policy_mgnt}/edit-policy-get/__POLICY_NAME__"
        self.endpoints["query_one_policy"]["verb"] = "GET"

        self.endpoints["query_all_switches"]["path"] = f"{self.endpoint_lan_fabric}/rest/inventory/allswitches"
        self.endpoints["query_all_switches"]["verb"] = "GET"

        self.endpoints["query_issu"]["path"] = f"{self.endpoint_package_mgnt}/issu"
        self.endpoints["query_issu"]["verb"] = "GET"

        self.endpoints["upgrade_image"]["path"] = f"{self.endpoint_image_upgrade}/upgrade-image"
        self.endpoints["upgrade_image"]["verb"] = "POST"

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

class DcnmImageUpgrade(DcnmImageUpgradeCommon):
    """
    Ansible support for image policy attach, detach, and query.
    """
    def __init__(self, module):
        super().__init__(module)

        # populated in self.build_attach_policy_payload()
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

        Determine current image policy state on NDFC
        """
        path = self.endpoints["query_all_policies"]["path"]
        verb = self.endpoints["query_all_policies"]["verb"]
        self.have = dcnm_send(self.module, verb, path)
        result = self._handle_get_response(self.have)
        if not result["success"]:
            msg = "Unable to retrieve image policy information from NDFC"
            self.module.fail_json(msg=msg)

    def get_want(self):
        """
        Caller: main()

        Update self.want_create for all switches defined in the playbook
        """
        self._merge_global_and_switch_configs(self.config)
        self._validate_switch_configs()
        want_create = self.switch_configs
        if not want_create:
            return
        self.want_create = want_create

    def get_diff_merge(self):
        """
        Caller: main()

        Populates self.diff_create list() with items from our want list
        that are not in our have list.  These items will be sent to NDFC.
        """
        diff_create = []

        for want_create in self.want_create:
            found = False
            for have_create in self.have_create:
                if want_create["policy"] == have_create["policy"]:
                    found = True
            if not found:
                diff_create.append(want_create)
        self.diff_create = diff_create

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

    def build_attach_policy_payload(self):
        self.payloads = []
        for switch in self.switch_configs:
            self.switch_details.ip_address = switch.get('ip_address')
            self.image_policies.policy_name = switch.get('policy')

            if self.image_policies.name is None:
                msg = f"policy {switch.get('policy')} does not exist on NDFC"
                self.module.fail_json(msg=msg)

            if self.switch_details.platform not in self.image_policies.platform:
                msg = f"policy {switch.get('policy')} does not support platform "
                msg += f"{self.switch_details.platform}. {switch.get('policy')} "
                msg += f"supports the following platform(s): {self.image_policies.platform}"
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
                    msg += f"Please verify that the switch is managed by NDFC"
                    self.module.fail_json(msg=msg)
            self.payloads.append(payload)

    def attach_policies(self):
        self.build_attach_policy_payload()
        path = self.endpoints["attach_policy"]["path"]
        verb = self.endpoints["attach_policy"]["verb"]
        payload = {}
        payload["mappingList"] = self.payloads
        response = dcnm_send(self.module, verb, path, data=json.dumps(payload))
        result = self._handle_post_put_response(response, "POST")

        if not result["success"]:
            self._failure(response)

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
        path = self.endpoints["query_all_switches"]["path"]
        verb = self.endpoints["query_all_switches"]["verb"]
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
        path = self.endpoints["query_all_policies"]["path"]
        verb = self.endpoints["query_all_policies"]["verb"]
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

        Refresh switch_details with current switch details from NDFC
        """
        path = self.endpoints["query_all_switches"]["path"]
        verb = self.endpoints["query_all_switches"]["verb"]
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
            "Compliance"
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

        Possible values:
            "In-Sync"
            "Out-Of-Sync"
        """
        return self._get("status")

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
        dcnm_module.attach_policies()

    module.exit_json(**dcnm_module.result)

if __name__ == "__main__":
    main()
