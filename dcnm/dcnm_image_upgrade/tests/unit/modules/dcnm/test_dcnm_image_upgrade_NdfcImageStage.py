from dcnm_image_upgrade.dcnm_image_upgrade import (
    NdfcAnsibleImageUpgradeCommon, NdfcSwitchIssuDetailsBySerialNumber, NdfcImageStage, NdfcVersion
)
from dcnm_image_upgrade.tests.unit.modules.dcnm.fixture import load_fixture
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import (
    AnsibleFailJson,
)
from ansible.module_utils.basic import AnsibleModule
import pytest
from typing import Any, Dict

"""
ndfc_version: 12
description: Verify functionality of subclass NdcImageStage
"""
class_name = "NdfcImageStage"
response_file = f"dcnm_image_upgrade_responses_{class_name}"

# Here, we are using the superclass name, since we are sharing the
# same response file across all subclasses.
class_name = "NdfcSwitchIssuDetails"
response_file_issu_details = f"dcnm_image_upgrade_responses_{class_name}"

class_name = "NdfcVersion"
response_file_ndfc_version = f"dcnm_image_upgrade_responses_{class_name}"

def response_data_issu_details(key: str) -> Dict[str, str]:
    response = load_fixture(response_file_issu_details).get(key)
    print(f"response_data_issu_details: {key} : {response}")
    return response

def response_data_ndfc_version(key: str) -> Dict[str, str]:
    response = load_fixture(response_file_ndfc_version).get(key)
    print(f"response_data: {key} : {response}")
    return response

def response_data(key: str) -> Dict[str, str]:
    response = load_fixture(response_file).get(key)
    print(f"response_data: {key} : {response}")
    return response

@pytest.fixture
def mock_ndfc_switch_issu_details_by_serial_number(monkeypatch) -> NdfcSwitchIssuDetailsBySerialNumber:

    def mock_dcnm_send(*args, **kwargs) -> Dict[str, Any]:
        return response_data_issu_details("NdfcImageStage_test_prune_serial_numbers")

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.dcnm_send", mock_dcnm_send)

    return NdfcSwitchIssuDetailsBySerialNumber(MockAnsibleModule)


class MockAnsibleModule:
    params = {}

    def fail_json(msg) -> AnsibleFailJson:
        raise AnsibleFailJson(msg)

@pytest.fixture
def module():
    return NdfcImageStage(MockAnsibleModule)

def test_init_properties(module) -> None:
    """
    Properties are initialized to expected values
    """
    module._init_properties()
    assert isinstance(module.properties, dict)
    assert module.properties.get("ndfc_data") == None
    assert module.properties.get("ndfc_response") == None
    assert module.properties.get("ndfc_result") == None
    assert module.properties.get("serial_numbers") == None
    assert module.properties.get("check_interval") == 10
    assert module.properties.get("check_timeout") == 1800

def test_prune_serial_numbers(module, mock_ndfc_switch_issu_details_by_serial_number) -> None:
    """
    prune_serial_numbers removes serial numbers from the list for which imageStaged == "Success"
    For this test, the ndfc response for the first three serial numbers in module.serial_numbers,
    i.e. ["FDO2112189M", "FDO211218AX", "FDO211218B5"] is "none", so these serial numbers are not 
    pruned.

    We expect to see the remaining serial numbers in module.serial_numbers, in the pruned list, i.e.
    ["FDO211218FV", "FDO211218GC"].
    """

    module.issu_detail = mock_ndfc_switch_issu_details_by_serial_number
    module.serial_numbers = ["FDO2112189M", "FDO211218AX", "FDO211218B5", "FDO211218FV", "FDO211218GC"]
    module.prune_serial_numbers()
    assert isinstance(module.serial_numbers, list)
    assert len(module.serial_numbers) == 3
    assert "FDO2112189M" in module.serial_numbers
    assert "FDO211218AX" in module.serial_numbers
    assert "FDO211218B5" in module.serial_numbers
    assert "FDO211218FV" not in module.serial_numbers
    assert "FDO211218GC" not in module.serial_numbers

