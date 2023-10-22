from dcnm_image_upgrade.dcnm_image_upgrade import NdfcAnsibleImageUpgradeCommon, NdfcImageInstallOptions
from dcnm_image_upgrade.tests.unit.modules.dcnm.fixture import load_fixture
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import (
    AnsibleFailJson,
)
import pytest
from typing import Any, Dict

"""
ndfc_version: 12
description: Verify functionality of class NdfcImageInstallOptions
"""
class_name = "NdfcImageInstallOptions"
response_file = f"dcnm_image_upgrade_responses_{class_name}"

class MockAnsibleModule:
    params = {}

    def fail_json(msg) -> AnsibleFailJson:
        raise AnsibleFailJson(msg)

def response_data(key: str) -> Dict[str, str]:
    response = load_fixture(response_file).get(key)
    print(f"{key} : : {response}")
    return response

@pytest.fixture
def module():
    return NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)

@pytest.fixture
def install_options_module(module):
    return NdfcImageInstallOptions(module)

def test_policy_name_not_defined() -> None:
    """ """
    test_module = NdfcImageInstallOptions(MockAnsibleModule)
    test_module.serial_number = "FOO"
    with pytest.raises(AnsibleFailJson, match=r"NdfcImageInstallOptions.refresh: instance.policy_name must be set before calling refresh\(\)"):
        test_module.refresh()

def test_serial_number_not_defined() -> None:
    """ """
    test_module = NdfcImageInstallOptions(MockAnsibleModule)
    test_module.policy_name = "FOO"
    with pytest.raises(AnsibleFailJson, match=r"NdfcImageInstallOptions.refresh: instance.serial_number must be set before calling refresh\(\)"):
        test_module.refresh()

def test_refresh_return_code_200(monkeypatch) -> None:
    """ """
    test_module = NdfcImageInstallOptions(MockAnsibleModule)
    key = "imageupgrade_install_options_post_return_code_200"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send)
    test_module.policy_name = "KRM5"
    test_module.serial_number = "BAR"
    test_module.refresh()
    assert isinstance(test_module.ndfc_response, dict)
    assert test_module.device_name == "cvd-1314-leaf"
    assert test_module.err_message == ""
    assert test_module.epld_modules is None
    assert test_module.install_option == "disruptive"
    assert test_module.install_packages is None
    assert test_module.os_type == "64bit"
    assert test_module.platform == "N9K/N3K"
    assert test_module.serial_number == "BAR"
    assert test_module.version == "10.2.5"
    assert test_module.comp_disp == "show install all impact nxos bootflash:nxos64-cs.10.2.5.M.bin"
    assert test_module.ndfc_result.get("success") == True

def test_refresh_return_code_500(monkeypatch) -> None:
    """ """
    test_module = NdfcImageInstallOptions(MockAnsibleModule)
    key = "imageupgrade_install_options_post_return_code_500"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send)
    test_module.policy_name = "KRM5"
    test_module.serial_number = "BAR"
    error_message = "NdfcImageInstallOptions.refresh: "
    error_message += "Bad result when retrieving install-options from NDFC"
    with pytest.raises(AnsibleFailJson, match=rf"{error_message}"):
        test_module.refresh()

def test_build_payload_defaults() -> None:
    """
    Currect defaults should be applied to the payload if the user does not
    specify them.  Specifically, issu, epld, and package_install.
    """
    test_module = NdfcImageInstallOptions(MockAnsibleModule)
    test_module.policy_name = "KRM5"
    test_module.serial_number = "BAR"
    test_module._build_payload()
    assert test_module.payload.get("devices")[0].get("policyName") == "KRM5"
    assert test_module.payload.get("devices")[0].get("serialNumber") == "BAR"
    assert test_module.payload.get("issu") == True
    assert test_module.payload.get("epld") == False
    assert test_module.payload.get("packageInstall") == False

def test_build_payload_user_changed_defaults() -> None:
    """
    Defaults should be overridden by the user if specified.  Specifically,
    issu, epld, and package_install.
    """
    test_module = NdfcImageInstallOptions(MockAnsibleModule)
    test_module.policy_name = "KRM5"
    test_module.serial_number = "BAR"
    test_module.issu = False
    test_module.epld = True
    test_module.package_install = True
    test_module._build_payload()
    assert test_module.payload.get("devices")[0].get("policyName") == "KRM5"
    assert test_module.payload.get("devices")[0].get("serialNumber") == "BAR"
    assert test_module.payload.get("issu") == False
    assert test_module.payload.get("epld") == True
    assert test_module.payload.get("packageInstall") == True
