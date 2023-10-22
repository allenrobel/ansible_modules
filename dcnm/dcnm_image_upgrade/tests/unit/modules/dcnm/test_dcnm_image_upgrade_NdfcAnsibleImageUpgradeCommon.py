from dcnm_image_upgrade.dcnm_image_upgrade import NdfcAnsibleImageUpgradeCommon
from dcnm_image_upgrade.tests.unit.modules.dcnm.fixture import load_fixture
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import (
    AnsibleFailJson,
)
import pytest
from typing import Dict

"""
ndfc_version: 12
description: Verify functionality of class NdfcAnsibleImageUpgradeCommon
"""
class_name = "NdfcAnsibleImageUpgradeCommon"
response_file = f"dcnm_image_upgrade_responses_{class_name}"

class MockAnsibleModule:
    params = {}

    def fail_json(msg) -> dict:
        raise AnsibleFailJson(msg)

@pytest.fixture
def module():
    return NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)

def response_data(key: str) -> Dict[str, str]:
    response = load_fixture(response_file).get(key)
    verb = response.get("METHOD")
    print(f"{key} : {verb} : {response}")
    return {"response": response, "verb": verb}

def test_handle_response_post_return_code_200(module) -> None:
    """
    verify _handle_reponse() return values for 200/OK response
    to POST request
    """
    data = response_data("mock_post_return_code_200_MESSAGE_OK")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("success") == True
    assert result.get("changed") == True


def test_handle_response_post_MESSAGE_not_OK(module) -> None:
    """
    verify _handle_reponse() return values for 400/NOT OK response
    to POST request
    """
    data = response_data("mock_post_return_code_400_MESSAGE_NOT_OK")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("success") == False
    assert result.get("changed") == False


def test_handle_response_post_ERROR_key_present(module) -> None:
    """
    verify _handle_reponse() return values for 200 response 
    to POST request when an ERROR key is present in the response
    """
    data = response_data("mock_post_return_code_200_ERROR_key_present")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("success") == False
    assert result.get("changed") == False


def test_handle_response_get_return_code_200_MESSAGE_OK(module) -> None:
    """
    verify _handle_response() return values for 200 response
    to GET request when MESSAGE key == "OK"
    """
    data = response_data("mock_get_return_code_200_MESSAGE_OK")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("found") == True
    assert result.get("success") == True


def test_handle_response_get_return_code_404_MESSAGE_not_found(module) -> None:
    """
    verify _handle_response() return values for 404 response
    to GET request when MESSAGE key == "Not Found"
    """
    data = response_data("mock_get_return_code_404_MESSAGE_not_found")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("found") == False
    assert result.get("success") == True


def test_handle_response_get_return_code_500_MESSAGE_OK(module) -> None:
    """
    verify _handle_response() return values for 500 response
    to GET request when MESSAGE key == "OK"
    """
    data = response_data("mock_get_return_code_500_MESSAGE_OK")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("found") == False
    assert result.get("success") == False


def test_handle_response_get_return_code_200_MESSAGE_not_OK(module) -> None:
    """
    verify _handle_response() return values for 200 response
    to GET request when MESSAGE key != "OK"
    """
    data = response_data("mock_get_return_code_200_MESSAGE_not_OK")
    result = module._handle_response(data.get("response"), data.get("verb"))
    assert result.get("found") == False
    assert result.get("success") == False


def test_handle_response_unknown_response_verb(module) -> None:
    """
    verify that fail_json() is called if a unknown request verb is provided
    """
    data = response_data("mock_unknown_response_verb")
    with pytest.raises(AnsibleFailJson, match=r"Unknown request verb \(FOO\)"):
        module._handle_response(data.get("response"), data.get("verb"))


def test_dcnm_image_upgrade_common_make_boolean(module) -> None:
    """
    verify that make_boolean() returns expected values for all cases
    """
    for value in ["True", "true", "TRUE", True]:
        assert module.make_boolean(value) == True
    for value in ["False", "false", "FALSE", False]:
        assert module.make_boolean(value) == False
    for value in ["foo", 1, 0, None, {"foo": 10}, [1, 2, "3"]]:
        assert module.make_boolean(value) == value


def test_dcnm_image_upgrade_common_make_none(module) -> None:
    """
    verify that make_none() returns expected values for all cases
    """
    for value in ["", "none", "None", "NONE", "null", "Null", "NULL", None]:
        assert module.make_none(value) == None
    for value in ["foo", 1, 0, True, False, {"foo": 10}, [1, 2, "3"]]:
        assert module.make_none(value) == value
