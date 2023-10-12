class DcnmImageStageInfo(DcnmImageUpgradeCommon):
    """
    This uses an unpublished endpoint, so let's not use it for now.

    We were going to use this to get free space on the switch bootflash
    but hopefully stage-image will do that for us.

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/policymgnt/stage-info?serialNumber=FDO211218HH

    Response:
    [{
        "serialNumber": "FDO211218HH",
        "deviceName": "cvd-1313-leaf",
        "primary": "49013579776",
        "secodnory": "N/A",
        "requiredSpace": 0,
        "stagingFiles": [{
            "fileName": "nxos64-cs.10.3.2.F.bin",
            "size": "0"
        }]
    }]
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["serial_number"] = None
