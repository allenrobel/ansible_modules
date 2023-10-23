from dcnm_image_upgrade.dcnm_image_upgrade import (
    NdfcSwitchIssuDetailsByIpAddress
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
# Here, we are using the superclass name, since we are sharing the
# same response file across all subclasses.
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
    return NdfcSwitchIssuDetailsByIpAddress(MockAnsibleModule)


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
    assert isinstance(module.ndfc_data, list)

def test_properties_are_set_to_expected_values(monkeypatch, module) -> None:
    """
    Properties are set based on ip_address setter value.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issu
    """
    key = "packagemgnt_issu_get_return_code_200_many_switch"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    module.refresh()
    module.ip_address = "172.22.150.102"
    assert module.serial_number == "FDO21120U5D"
    # change ip_address to a different switch, expect different information
    module.ip_address = "172.22.150.108"
    assert module.serial_number == "FDO2112189M"
    assert module.device_name == "cvd-2313-leaf"

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
    endpoint: .../api/v1/imagemanagement/rest/policymgnt/policiess
    """
    key = "packagemgnt_issu_get_return_code_404"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
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
    error_message = "NdfcSwitchIssuDetailsByIpAddress.refresh: "
    error_message += "NDFC has no switch ISSU information."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()

def test_ndfc_result_return_code_200_ndfc_switch_issu_info_length_0(monkeypatch, module) -> None:
    """
    fail_json is called on 200 response with DATA.lastOperDataObject length 0.
    endpoint: .../api/v1/imagemanagement/rest/policymgnt/policiess
    """
    key = "packagemgnt_issu_get_return_code_200"
    key += "_ndfc_switch_issu_info_length_0"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send",
        mock_dcnm_send
    )
    error_message = "NdfcSwitchIssuDetailsByIpAddress.refresh: "
    error_message += "NDFC has no switch ISSU information."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()
