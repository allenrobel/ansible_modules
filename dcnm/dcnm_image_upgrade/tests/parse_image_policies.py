#!/usr/bin/env python
# endpoint
# /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/policies

from ansible.module_utils.basic import AnsibleModule

data = {'status': 'SUCCESS', 'lastOperDataObject': [{'policyName': 'NR3F', 'policyType': 'PLATFORM', 'nxosVersion': '10.3.2_nxos64-cs_64bit', 'packageName': '', 'platform': 'N9K/N3K', 'policyDescr': '', 'platformPolicies': '', 'epldImgName': '', 'rpmimages': '', 'imageName': 'nxos64-cs.10.3.2.F.bin', 'agnostic': False, 'ref_count': 1}], 'message': ''}

class ImagePolicies:
    def __init__(self, module):
        self.module = module
        properties = {}
        properties["name"] = None
        self.build_image_policies()


    def build_image_policies(self):
        """
        Return dictionary keyed on policyName with value of dictionary of policy details
        """
        self.image_policies = {}
        for policy in data["lastOperDataObject"]:
            self.image_policies[policy["policyName"]] = policy

    def get(self, item):
        if self.name is None:
            msg = f"{self.__class__.__name__}: instance.name must be set "
            msg += "before accessing properties."
            self.module.fail_json(msg=msg)
        return self.image_policies.get(item)

    @property
    def name(self):
        """
        Return the name of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.properties.get("name")
    @name.setter
    def name(self, value):
        self.properties["name"] = value

    @property
    def policy_type(self):
        """
        Return the policyType of the policy with self.name, if it exists.
        Return None otherwise
        """
        return self.get("policyType")

    @property
    def nxos_version(self):
        """
        Return the nxosVersion of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("nxosVersion")

    @property
    def package_name(self):
        """
        Return the packageName of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("nxosVersion")

    @property
    def platform(self):
        """
        Return the platform of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("platform")

    @property
    def description(self):
        """
        Return the policyDescr of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("policyDescr")

    @property
    def platform_policies(self):
        """
        Return the platformPolicies of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("platformPolicies")

    @property
    def epld_image_name(self):
        """
        Return the epldImgName of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("epldImgName")

    @property
    def rpm_images(self):
        """
        Return the rpmimages of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("rpmimages")

    @property
    def image_name(self):
        """
        Return the imageName of the policy with policy_name, if it exists.
        Return None otherwise
        """
        return self.get("imageName")

    @property
    def agnostic(self):
        """
        Return the value of agnostic for the policy with policy_name,
        if it exists.
        Return None otherwise
        """
        return self.get("agnostic")

def main():
    element_spec = dict(
        config=dict(required=False, type="dict"),
        state=dict(default="merged", choices=["merged"]),
    )

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)

    instance = ImagePolicies(module)
    instance.name = "NR3F"

    for property in [instance.policy_type, instance.nxos_version, instance.package_name, instance.platform, instance.description, instance.platform_policies, instance.epld_image_name, instance.rpm_images, instance.image_name, instance.agnostic]:
        print("{:<25} {:<50}".format(property.__name__, function(property)))

    module.exit_json(True)

if __name__ == "__main__":
    main()
