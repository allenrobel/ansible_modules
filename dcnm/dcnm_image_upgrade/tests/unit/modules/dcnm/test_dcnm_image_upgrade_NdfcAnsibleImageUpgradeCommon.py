from dcnm_image_upgrade.dcnm_image_upgrade import NdfcAnsibleImageUpgradeCommon
from dcnm_image_upgrade.tests.unit.modules.dcnm.dcnm_module import loadPlaybookData
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    ModuleTestCase,
)
import pytest

# Uncomment if we need this later...
# from pytest import MonkeyPatch
"""
ndfc_version: 12
description: Verify functionality of class NdfcAnsibleImageUpgradeCommon
"""
class MockAnsibleModule:
    params={}
    def fail_json(msg) -> dict:
        raise AnsibleFailJson(msg)
    # argument_spec={}
    # supports_check_mode=True

response_file = "dcnm_image_upgrade_responses"

def test_dcnm_image_upgrade_common_handle_response_post_return_code_200() -> None:
    """
    """
    response_key = "mock_post_return_code_200_MESSAGE_OK"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("success") == True
    assert result.get("changed") == True

def test_dcnm_image_upgrade_common_handle_response_post_MESSAGE_not_OK() -> None:
    """
    """
    response_key = "mock_post_return_code_400_MESSAGE_NOT_OK"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("success") == False
    assert result.get("changed") == False

def test_dcnm_image_upgrade_common_handle_response_post_ERROR_key_present() -> None:
    """
    """
    response_key = "mock_post_return_code_200_ERROR_key_present"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("success") == False
    assert result.get("changed") == False

def test_dcnm_image_upgrade_common_handle_response_get_return_code_200_MESSAGE_OK() -> None:
    """
    """
    response_key = "mock_get_return_code_200_MESSAGE_OK"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {verb} : {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("found") == True
    assert result.get("success") == True

def test_dcnm_image_upgrade_common_handle_response_get_return_code_404_MESSAGE_not_found() -> None:
    """
    """
    response_key = "mock_get_return_code_404_MESSAGE_not_found"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {verb} : {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("found") == False
    assert result.get("success") == True

def test_dcnm_image_upgrade_common_handle_response_get_return_code_500_MESSAGE_OK() -> None:
    """
    """
    response_key = "mock_get_return_code_500_MESSAGE_OK"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {verb} : {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("found") == False
    assert result.get("success") == False

def test_dcnm_image_upgrade_common_handle_response_get_return_code_200_MESSAGE_not_OK() -> None:
    """
    """
    response_key = "mock_get_return_code_200_MESSAGE_not_OK"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {verb} : {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = module._handle_response(response_data, verb)
    assert result.get("found") == False
    assert result.get("success") == False

def test_dcnm_image_upgrade_common_handle_response_unknown_response_verb() -> None:
    """
    """
    response_key = "mock_unknown_response_verb"
    response_data = loadPlaybookData(response_file).get(response_key)
    verb = response_data.get("METHOD")

    print(f"{response_key}: {verb} : {response_data}")

    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    with pytest.raises(AnsibleFailJson, match=r"Unknown request verb \(FOO\)"):
        result = module._handle_response(response_data, verb)

def test_dcnm_image_upgrade_common_make_boolean() -> None:
    """
    """
    module = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    assert module.make_boolean("True") == True
    assert module.make_boolean("False") == False
    assert module.make_boolean("true") == True
    assert module.make_boolean("false") == False
    assert module.make_boolean(True) == True
    assert module.make_boolean(False) == False
    assert module.make_boolean("foo") == "foo"
    assert module.make_boolean(1) == 1
    assert module.make_boolean(0) == 0
    assert module.make_boolean(None) == None
    assert module.make_boolean({"foo": 10}) == {"foo": 10}
    assert module.make_boolean([1,2,"3"]) == [1,2,"3"]

'''
# Example of using monkeypatch if we need to patch a property
# Not needed so far, but keep this around for reference
# Uncomment the pytest import at the top of the file if we need this later...
def test_dcnm_image_upgrade_endpoints_image_stage_monkeypatch(monkeypatch) -> None:
    """
    :param monkeypatch:
    :return: None
    """
    @property
    def mock_image_stage(self) -> dict:
        path = f"/stage-image"
        endpoint = {}
        endpoint["path"] = path
        endpoint["verb"] = "POST"
        return endpoint

    monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.NdfcEndpoints.image_stage", mock_image_stage)

    endpoints = NdfcEndpoints()
    assert endpoints.image_stage.get("verb") == "POST"
    assert endpoints.image_stage.get("path") == "/stage-image"
'''