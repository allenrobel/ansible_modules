# this went into dcnm_image_upgrade.py
# Replaced it with handle_query_state()
# This is a backup
def handle_query_policies(self):
        """
        Query the image policy

        Caller: main()
        """
        msg = f"REMOVE: {self.class_name}.handle_query_state: "
        msg += f"Entered. self.need {self.need}"
        self.log_msg(msg)
        query_image_policies = set()
        for switch in self.need:
            self.switch_details.ip_address = switch.get("ip_address")
            self.image_policies.policy_name = switch.get("policy")
            query_image_policies.add(self.image_policies.name)
        msg = f"REMOVE: {self.class_name}.handle_query_state: "
        msg += f"query_policies: {query_image_policies}"
        self.log_msg(msg)
        if len(query_image_policies) == 0:
            self.result = dict(changed=False, diff=[], response=[])
            return
        instance = NdfcImagePolicyAction(self.module)
        for policy_name in sorted(list(query_image_policies)):
            msg = f"REMOVE: {self.class_name}.handle_query_state: "
            msg += f"query policy_name: {policy_name}"
            self.log_msg(msg)
            instance.policy_name = policy_name
            instance.action = "query"
            # instance.serial_numbers = ["none"]
            instance.commit()
            if instance.query_result is None:
                continue
            self.result["response"].append(instance.query_result)
        self.result["diff"] = []
        self.result["changed"] = False
