from dcnm_image_upgrade.dcnm_image_upgrade import NdfcEndpoints

"""
ndfc_version: 12
description: Verify that class NdfcEndpoints returns the correct endpoints
"""


def test_dcnm_image_upgrade_endpoints_init() -> None:
    """
    Endpoints.__init__
    """
    endpoints = NdfcEndpoints()
    endpoints.__init__()
    assert endpoints.endpoint_api_v1 == "/appcenter/cisco/ndfc/api/v1"
    assert endpoints.endpoint_feature_manager == "/appcenter/cisco/ndfc/api/v1/fm"
    assert (
        endpoints.endpoint_image_management
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement"
    )
    assert (
        endpoints.endpoint_image_upgrade
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imageupgrade"
    )
    assert endpoints.endpoint_lan_fabric == "/appcenter/cisco/ndfc/api/v1/lan-fabric"
    assert (
        endpoints.endpoint_package_mgnt
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/packagemgnt"
    )
    assert (
        endpoints.endpoint_policy_mgnt
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt"
    )
    assert (
        endpoints.endpoint_staging_management
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/stagingmanagement"
    )


def test_dcnm_image_upgrade_endpoints_bootflash_info() -> None:
    """
    Endpoints.bootflash_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.bootflash_info.get("verb") == "GET"
    assert (
        endpoints.bootflash_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imagemgnt/bootFlash/bootflash-info"
    )


def test_dcnm_image_upgrade_endpoints_install_options() -> None:
    """
    Endpoints.install_options
    """
    endpoints = NdfcEndpoints()
    assert endpoints.install_options.get("verb") == "POST"
    assert (
        endpoints.install_options.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imageupgrade/install-options"
    )


def test_dcnm_image_upgrade_endpoints_image_stage() -> None:
    """
    Endpoints.image_stage
    """
    endpoints = NdfcEndpoints()
    assert endpoints.image_stage.get("verb") == "POST"
    assert (
        endpoints.image_stage.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/stagingmanagement/stage-image"
    )


def test_dcnm_image_upgrade_endpoints_image_upgrade() -> None:
    """
    Endpoints.image_upgrade
    """
    endpoints = NdfcEndpoints()
    assert endpoints.image_upgrade.get("verb") == "POST"
    assert (
        endpoints.image_upgrade.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imageupgrade/upgrade-image"
    )


def test_dcnm_image_upgrade_endpoints_image_validate() -> None:
    """
    Endpoints.image_validate
    """
    endpoints = NdfcEndpoints()
    assert endpoints.image_validate.get("verb") == "POST"
    assert (
        endpoints.image_validate.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/stagingmanagement/validate-image"
    )


def test_dcnm_image_upgrade_endpoints_issu_info() -> None:
    """
    Endpoints.issu_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.issu_info.get("verb") == "GET"
    assert (
        endpoints.issu_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/packagemgnt/issu"
    )


def test_dcnm_image_upgrade_endpoints_ndfc_version() -> None:
    """
    Endpoints.ndfc_version
    """
    endpoints = NdfcEndpoints()
    assert endpoints.ndfc_version.get("verb") == "GET"
    assert (
        endpoints.ndfc_version.get("path")
        == "/appcenter/cisco/ndfc/api/v1/fm/about/version"
    )


def test_dcnm_image_upgrade_endpoints_policies_attached_info() -> None:
    """
    Endpoints.policies_attached_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.policies_attached_info.get("verb") == "GET"
    assert (
        endpoints.policies_attached_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/all-attached-policies"
    )


def test_dcnm_image_upgrade_endpoints_policies_info() -> None:
    """
    Endpoints.policies_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.policies_info.get("verb") == "GET"
    assert (
        endpoints.policies_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/policies"
    )


def test_dcnm_image_upgrade_endpoints_policy_attach() -> None:
    """
    Endpoints.policy_attach
    """
    endpoints = NdfcEndpoints()
    assert endpoints.policy_attach.get("verb") == "POST"
    assert (
        endpoints.policy_attach.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/attach-policy"
    )


def test_dcnm_image_upgrade_endpoints_policy_create() -> None:
    """
    Endpoints.policy_create
    """
    endpoints = NdfcEndpoints()
    assert endpoints.policy_create.get("verb") == "POST"
    assert (
        endpoints.policy_create.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/platform-policy"
    )


def test_dcnm_image_upgrade_endpoints_policy_detach() -> None:
    """
    Endpoints.policy_detach
    """
    endpoints = NdfcEndpoints()
    assert endpoints.policy_detach.get("verb") == "DELETE"
    assert (
        endpoints.policy_detach.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/detach-policy"
    )


def test_dcnm_image_upgrade_endpoints_policy_info() -> None:
    """
    Endpoints.policy_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.policy_info.get("verb") == "GET"
    assert (
        endpoints.policy_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/image-policy/__POLICY_NAME__"
    )


def test_dcnm_image_upgrade_endpoints_stage_info() -> None:
    """
    Endpoints.stage_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.stage_info.get("verb") == "GET"
    assert (
        endpoints.stage_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/imagemanagement/rest/stagingmanagement/stage-info"
    )


def test_dcnm_image_upgrade_endpoints_switches_info() -> None:
    """
    Endpoints.switches_info
    """
    endpoints = NdfcEndpoints()
    assert endpoints.switches_info.get("verb") == "GET"
    assert (
        endpoints.switches_info.get("path")
        == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches"
    )


# Example of using monkeypatch if we need to patch a property
# Not needed in this case, but keep this around for reference
# def test_dcnm_image_upgrade_endpoints_image_stage_monkeypatch(monkeypatch) -> None:
#     """
#     :param monkeypatch:
#     :return: None
#     """
#     @property
#     def mock_image_stage(self) -> dict:
#         path = f"/stage-image"
#         endpoint = {}
#         endpoint["path"] = path
#         endpoint["verb"] = "POST"
#         return endpoint

#     monkeypatch.setattr("dcnm_image_upgrade.dcnm_image_upgrade.NdfcEndpoints.image_stage", mock_image_stage)

#     endpoints = NdfcEndpoints()
#     assert endpoints.image_stage.get("verb") == "POST"
#     assert endpoints.image_stage.get("path") == "/stage-image"
