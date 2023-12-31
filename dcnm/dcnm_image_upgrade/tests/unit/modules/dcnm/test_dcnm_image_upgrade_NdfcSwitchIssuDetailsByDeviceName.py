from typing import Any, Dict

import pytest
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import \
    AnsibleFailJson
from dcnm_image_upgrade.dcnm_image_upgrade import \
    NdfcSwitchIssuDetailsByDeviceName
from dcnm_image_upgrade.tests.unit.modules.dcnm.fixture import load_fixture

"""
ndfc_version: 12
description: Verify functionality of subclass NdfcSwitchIssuDetailsByDeviceName
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
    return NdfcSwitchIssuDetailsByDeviceName(MockAnsibleModule)


def test_init_properties(module) -> None:
    """
    Properties are initialized to expected values
    """
    action_keys = {"imageStaged", "upgrade", "validated"}

    module._init_properties()
    assert isinstance(module.properties, dict)
    assert isinstance(module.properties.get("action_keys"), set)
    assert module.properties.get("action_keys") == action_keys
    assert module.properties.get("ndfc_data") == None
    assert module.properties.get("ndfc_response") == None
    assert module.properties.get("ndfc_result") == None
    assert module.properties.get("device_name") == None


def test_refresh_return_code_200(monkeypatch, module) -> None:
    """
    NDFC response data for 200 response has expected types.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issu

    """
    key = "packagemgnt_issu_get_return_code_200_one_switch"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr(
        "dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send
    )
    module.refresh()
    assert isinstance(module.ndfc_response, dict)
    assert isinstance(module.ndfc_data, list)


def test_properties_are_set_to_expected_values(monkeypatch, module) -> None:
    """
    Properties are set based on device_name setter value.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issu
    """
    key = "packagemgnt_issu_get_return_code_200_many_switch"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr(
        "dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send
    )
    module.refresh()
    module.device_name = "leaf1"
    assert module.device_name == "leaf1"
    assert module.serial_number == "FDO21120U5D"
    # change device_name to a different switch, expect different information
    module.device_name = "cvd-2313-leaf"
    assert module.device_name == "cvd-2313-leaf"
    assert module.serial_number == "FDO2112189M"
    # verify remaining properties using current device_name
    assert module.eth_switch_id == 39890
    assert module.fabric == "hard"
    assert module.fcoe_enabled == False
    assert module.group == "hard"
    # NOTE: For "id" see switch_id below
    assert module.image_staged == "Success"
    assert module.image_staged_percent == 100
    assert module.ip_address == "172.22.150.108"
    assert module.issu_allowed == None
    assert module.last_upg_action == "2023-Oct-06 03:43"
    assert module.mds == False
    assert module.mode == "Normal"
    assert module.model == "N9K-C93180YC-EX"
    assert module.model_type == 0
    assert module.peer == None
    assert module.platform == "N9K"
    assert module.policy == "KR5M"
    assert module.reason == "Upgrade"
    assert module.role == "leaf"
    assert module.status == "In-Sync"
    assert module.status_percent == 100
    # NOTE: switch_id appears in the response data as "id"
    # NOTE: "id" is a python reserved keyword, so we changed the property name
    assert module.switch_id == 2
    assert module.sys_name == "cvd-2313-leaf"
    assert module.system_mode == "Normal"
    assert module.upg_groups == None
    assert module.upgrade == "Success"
    assert module.upgrade_percent == 100
    assert module.validated == "Success"
    assert module.validated_percent == 100
    assert module.version == "10.2(5)"
    # NOTE: Two vdc_id values exist in the response data for each switch.
    # NOTE: Namely, "vdcId" and "vdc_id"
    # NOTE: Properties are provided for both, as follows.
    # NOTE: vdc_id == vdcId
    # NOTE: vdc_id2 == vdc_id
    assert module.vdc_id == 0
    assert module.vdc_id2 == -1
    assert module.vpc_peer == None
    assert module.vpc_role == None


def test_ndfc_result_return_code_200(monkeypatch, module) -> None:
    """
    ndfc_result contains expected key/values on 200 response from endpoint.
    endpoint: .../api/v1/imagemanagement/rest/packagemgnt/issu
    """
    key = "packagemgnt_issu_get_return_code_200_one_switch"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr(
        "dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send
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

    monkeypatch.setattr(
        "dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send
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

    monkeypatch.setattr(
        "dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send
    )
    error_message = "NdfcSwitchIssuDetailsByDeviceName.refresh: "
    error_message += "NDFC has no switch ISSU information."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()


def test_ndfc_result_return_code_200_ndfc_switch_issu_info_length_0(
    monkeypatch, module
) -> None:
    """
    fail_json is called on 200 response with DATA.lastOperDataObject length 0.
    endpoint: .../api/v1/imagemanagement/rest/policymgnt/policiess
    """
    key = "packagemgnt_issu_get_return_code_200"
    key += "_ndfc_switch_issu_info_length_0"

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        print(f"mock_dcnm_send: {response_data(key)}")
        return response_data(key)

    monkeypatch.setattr(
        "dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send
    )
    error_message = "NdfcSwitchIssuDetailsByDeviceName.refresh: "
    error_message += "NDFC has no switch ISSU information."
    with pytest.raises(AnsibleFailJson, match=error_message):
        module.refresh()
