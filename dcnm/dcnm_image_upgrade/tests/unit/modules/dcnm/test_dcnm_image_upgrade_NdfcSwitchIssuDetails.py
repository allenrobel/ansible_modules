from dcnm_image_upgrade.dcnm_image_upgrade import (
    NdfcSwitchIssuDetails, NdfcSwitchIssuDetailsByIpAddress, NdfcAnsibleImageUpgradeCommon
)
from dcnm_image_upgrade.tests.unit.modules.dcnm.fixture import load_fixture
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import (
    AnsibleFailJson,
)
import pytest
from typing import Any, Dict

"""
ndfc_version: 12
description: Verify functionality of class NdfcSwitchIssuDetails
"""
class_name = "NdfcSwitchIssuDetails"
response_file = f"dcnm_image_upgrade_responses_{class_name}"

class MockAnsibleModule:
    params = {}

    def fail_json(msg) -> AnsibleFailJson:
        raise AnsibleFailJson(msg)

def response_data(key: str) -> Dict[str, str]:
    response = load_fixture(response_file).get(key)
    print(f"response_data: {key} : {response}")
    return response

@pytest.fixture
def module():
    return NdfcSwitchIssuDetailsByIpAddress(NdfcSwitchIssuDetails(NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)))
    # return NdfcSwitchIssuDetails(MockAnsibleModule)


def test_init_properties(module) -> None:
    """
    Properties are initialized to None
    """
    action_keys = {"imageStaged", "upgrade", "validated"}

    module._init_properties()
    assert isinstance(module.properties, dict)
    assert isinstance(module.properties.get("action_keys"), set)
    assert module.properties.get("action_keys") == action_keys
    assert module.properties.get("ndfc_data") == None
    assert module.properties.get("ndfc_response") == None
    assert module.properties.get("ndfc_result") == None


def test_refresh_return_code_200(monkeypatch, module) -> None:
    """
    Properties are initialized based on 200 response from endpoint.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issu

    """
    key = "packagemgnt_issu_get_return_code_200_one_switch"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    module.refresh()
    assert isinstance(module.ndfc_response, dict)

def test_ndfc_result_return_code_200(monkeypatch, module) -> None:
    """
    ndfc_result contains expected key/values on 200 response from endpoint.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issu
    """
    key = "packagemgnt_issu_get_return_code_200_one_switch"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    module.refresh()
    assert isinstance(module.ndfc_result, dict)
    assert module.ndfc_result.get("found") == True
    assert module.ndfc_result.get("success") == True

def test_ndfc_result_return_code_404(monkeypatch, module) -> None:
    """
    fail_json is called on 404 response from malformed endpoint.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issuu
    TODO: This does not raise.  Look into this later...
    """
    key = "packagemgnt_issu_get_return_code_404"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    def mock_fail_json(msg) -> AnsibleFailJson:
        raise AnsibleFailJson(msg)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.AnsibleModule.fail_json",
        mock_fail_json
    )
    error_message = "Bad result when retriving switch information from NDFC"
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()

def test_ndfc_result_return_code_200_empty_data(monkeypatch, module) -> None:
    """
    fail_json is called on 200 response with empty DATA key.
    endpoint: .../api/v1/imagemanagement/rest/policymgnt/policiess
    """
    key = "packagemgnt_issu_get_return_code_200_empty_DATA"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    error_message = "NdfcSwitchIssuDetails.refresh: Bad response when retrieving "
    error_message += "image policy information from NDFC."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()

def test_ndfc_result_return_code_200_ndfc_has_no_defined_image_policies(monkeypatch, module) -> None:
    """
    fail_json is called on 200 response with DATA.lastOperDataObject length 0.
    endpoint: .../api/v1/imagemanagement/rest/policymgnt/policiess
    """
    key = "policymgnt_policies_get_return_code_200"
    key += "_ndfc_has_no_defined_image_policies"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    error_message = "NdfcSwitchIssuDetails.refresh: "
    error_message += "NDFC has no defined image policies."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()

def test_policy_name_not_found(monkeypatch, module) -> None:
    """
    fail_json() is called if response does not contain policy_name.
    i.e. image policy with name FOO has not yet been created on NDFC.
    """
    key = "policymgnt_policies_get_return_code_200"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    module.refresh()
    module.policy_name = "FOO"
    error_message = "NdfcSwitchIssuDetails._get: "
    error_message += "policy_name FOO is not defined in NDFC"
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.policy_type == "PLATFORM"

def test_get_with_policy_name_None(module) -> None:
    """
    fail_json is called when _get() is called prior to setting policy_name.
    """
    error_message = "NdfcSwitchIssuDetails._get: instance.policy_name must be "
    error_message += "set before accessing property imageName."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module._get("imageName")

def test_ndfc_result_return_code_200_policy_name_missing_in_response(monkeypatch, module) -> None:
    """
    fail_json is called on 200 response with missing policyName key.
    endpoint: .../api/v1/imagemanagement/rest/policymgnt/policiess

    NOTE: This is to cover a check in NdfcSwitchIssuDetails.refresh() for a scenario that should never happen.
    TODO: Consider removing this check, and this testcase.
    """
    key = "policymgnt_policies_get_return_code_200"
    key += "_policyName_missing_in_response"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    error_message = "NdfcSwitchIssuDetails.refresh: "
    error_message += "Cannot parse NDFC policy information"
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()
