class DcnmBootflashInfo(DcnmImageUpgradeCommon):
    """
    We may not need this if stage-image does the checking of bootflash space
    for us and returns a reasonable error message...

    Retrieve bootflash information for a switch from NDFC and provide
    property accessors for the following:

        - primary_total_space (bootFlashSpaceMap["bootflash:"]["totalSpace"])
        - primary_free_space (bootFlashSpaceMap["bootflash:"]["freeSpace"])
        - primary_used_space (bootFlashSpaceMap["bootflash:"]["usedSpace"])
        TODO:2 add support for secondary bootflash when we find a switch with two supervisors

    Usage (where module is an instance of AnsibleModule):

    instance = DcnmBootflashInfo(module)
    instance.serial_number = "AB222222CD"
    instance.refresh()
    primary_free_space = instance.primary_free_space
    secondary_free_space = instance.secondary_free_space
    etc...

    Endpoint:
    /appcenter/cisco/ndfc/api/v1/imagemanagement/rest/imagemgnt/bootFlash/bootflash-info?serialNumber=<serial_number>

    {
        "requiredSpace": "0 MB",
        "partitions": [
            "bootflash:"
        ],
        "bootFlashSpaceMap": {
            "bootflash:": {
                "deviceName": "cvd-1313-leaf",
                "serialNumber": "FDO211218HH",
                "ipAddr": " 172.22.150.104",
                "name": "bootflash:",
                "totalSpace": 53586325504,
                "freeSpace": 49013579776,
                "usedSpace": 4572745728,
                "bootflash_type": "active"
            }
        },
        "bootFlashDataMap": {
            "bootflash:": [
                {
                    "deviceName": "cvd-1313-leaf",
                    "serialNumber": "FDO211218HH",
                    "ipAddr": " 172.22.150.104",
                    "fileName": ".rpmstore/",
                    "size": "0",
                    "filePath": "bootflash:.rpmstore/",
                    "bootflash_type": "active",
                    "date": "May 24 21:44:08 2023",
                    "name": "bootflash:"
                },
            ]
        }
    }    
    """
    def __init__(self, module):
        super().__init__(module)
        self._init_properties()
        self.refresh()

    def _init_properties(self):
        self.properties = {}
        self.properties["serial_number"] = None

    def refresh(self):
        """
        Refresh self.stage_info with current image staging state from NDFC
        """
        if self.properties["serial_number"] is None:
            msg = f"{self.__class__.__name__}: set instance.serial_number "
            msg += f"before calling refresh()."
            self.module.fail_json(msg=msg)

        path = f"{self.endpoints['bootflash_info']['path']}?serialNumber="
        path += f"{self.serial_number}"
        verb = self.endpoints["bootflash_info"]["verb"]
        response = dcnm_send(self.module, verb, path)

        result = self._handle_response(response, verb)
        if not result["success"]:
            msg = "Unable to retrieve image staging information from NDFC"
            self.module.fail_json(msg=msg)

        data = response.get("DATA").get("bootFlashSpaceMap")
        if data is None:
            msg = "Unable to retrieve bootflash information from NDFC"
            self.module.fail_json(msg=msg)
        self.data = {}
        for flash_device in data.keys():
            if flash_device == "bootflash:":
                self.data["primary_total_space"] = data[flash_device]["totalSpace"]
                self.data["primary_free_space"] = data[flash_device]["freeSpace"]
                self.data["primary_used_space"] = data[flash_device]["usedSpace"]
            if flash_device == "remote-bootflash:":
                self.data["secondary_total_space"] = data[flash_device]["totalSpace"]
                self.data["secondary_free_space"] = data[flash_device]["freeSpace"]
                self.data["secondary_used_space"] = data[flash_device]["usedSpace"]

    def _get(self, item):
        if self.policy_name is None:
            msg = f"{self.__class__.__name__}: instance.policy_name must "
            msg += f"be set before accessing property {item}."
            self.module.fail_json(msg=msg)
        return self.data[self.policy_name].get(item)

    @property
    def serial_number(self):
        """
        Set the serial_number of the switch to query.
        """
        return self.properties.get("serial_number")
    @serial_number.setter
    def serial_number(self, value):
        self.properties["serial_number"] = value
