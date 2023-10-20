from dcnm_image_upgrade.dcnm_image_upgrade import NdfcAnsibleImageUpgradeCommon
from dcnm_image_upgrade.tests.unit.modules.dcnm.dcnm_module import loadPlaybookData
from pytest import MonkeyPatch
"""
ndfc_version: 12
description: Verify functionality of class NdfcAnsibleImageUpgradeCommon
"""
class MockAnsibleModule:
    params={}
    # argument_spec={}
    # supports_check_mode=True

def test_dcnm_image_upgrade_common_handle_response_post_return_code_200(monkeypatch) -> None:
    """
    """
    response_data = loadPlaybookData("dcnm_image_upgrade_responses").get("mock_post_return_code_200_MESSAGE_OK")
    print(f"mock_post_return_code_200_MESSAGE_OK: {response_data}")
    common = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = common._handle_response(response_data, "POST")
    assert result.get("success") == True
    assert result.get("changed") == True

def test_dcnm_image_upgrade_common_handle_response_post_MESSAGE_not_OK(monkeypatch) -> None:
    """
    """
    response_data = loadPlaybookData("dcnm_image_upgrade_responses").get("mock_post_return_code_400_MESSAGE_NOT_OK")
    print(f"mock_post_return_code_400_MESSAGE_NOT_OK: {response_data}")
    common = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = common._handle_response(response_data, "POST")
    assert result.get("success") == False
    assert result.get("changed") == False

def test_dcnm_image_upgrade_common_handle_response_post_ERROR_key_present(monkeypatch) -> None:
    """
    """
    response_data = loadPlaybookData("dcnm_image_upgrade_responses").get("mock_post_return_code_200_ERROR_key_present")
    print(f"mock_post_return_code_200_ERROR_key_present: {response_data}")
    common = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = common._handle_response(response_data, "POST")
    assert result.get("success") == False
    assert result.get("changed") == False

def test_dcnm_image_upgrade_common_handle_response_get_return_code_200(monkeypatch) -> None:
    """
    """
    response_data = loadPlaybookData("dcnm_image_upgrade_responses").get("mock_post_return_code_200_ERROR_key_present")
    print(f"mock_post_return_code_200_ERROR_key_present: {response_data}")
    common = NdfcAnsibleImageUpgradeCommon(MockAnsibleModule)
    result = common._handle_response(response_data, "POST")
    assert result.get("success") == False
    assert result.get("changed") == False

'''
# Example of using monkeypatch if we need to patch a property
# Not needed in this case, but keep this around for reference
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