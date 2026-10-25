import csv
from pathlib import Path


class PolicyEngine:

    def __init__(self, dataset_dir):

        self.dataset_dir = Path(dataset_dir)

        self.rules = []

        self.load_rules()

    # =========================================================
    # LOAD POLICY RULES
    # =========================================================

    def load_rules(self):

        file_path = (
            self.dataset_dir
            / "deletion_rules.csv"
        )

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            self.rules = list(reader)

    # =========================================================
    # FIND RULE
    # =========================================================

    def get_rule(self, data_category):

        for rule in self.rules:

            if (
                rule["data_category"]
                == data_category
            ):

                return rule

        return None

    # =========================================================
    # APPLY POLICY
    # =========================================================

    def evaluate(self, data_category, state):

        rule = self.get_rule(
            data_category
        )

        if rule is None:

            return {
                "matched": False,
                "data_category": data_category,
                "action": None,
                "condition": None,
                "rule_id": None,
                "reason": "No policy rule found"
            }

        condition = rule["condition"]
        required_action = rule["required_action"]

        # -----------------------------------------------------
        # OBSERVATION IS NOT PROOF OF A RETAINED RECORD
        # -----------------------------------------------------

        if state == "OBSERVATION":

            return {
                "matched": True,
                "data_category": data_category,
                "action": None,
                "condition": condition,
                "rule_id": rule["rule_id"],
                "reason": (
                    "Observation does not prove "
                    "that the record exists"
                )
            }

        # -----------------------------------------------------
        # ALWAYS
        # -----------------------------------------------------

        if condition == "Always":

            return {
                "matched": True,
                "data_category": data_category,
                "action": required_action,
                "condition": condition,
                "rule_id": rule["rule_id"],
                "reason": (
                    "Policy condition is Always"
                )
            }

        # -----------------------------------------------------
        # SUPPORT MESSAGE
        # -----------------------------------------------------

        if data_category == "SUPPORT_MESSAGE":

            if (
                "shared customer" in condition.lower()
                or "agent" in condition.lower()
                or "order context" in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "REDACT",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Shared support context must "
                        "be retained while customer data "
                        "is redacted"
                    )
                }

        # -----------------------------------------------------
        # SUPPORT ATTACHMENT
        # -----------------------------------------------------

        if data_category == "SUPPORT_ATTACHMENT":

            if (
                "belongs only to the deletion subject"
                in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "DELETE",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Attachment belongs only "
                        "to the deletion subject"
                    )
                }

        # -----------------------------------------------------
        # ANALYTICS / TELEMETRY
        # -----------------------------------------------------

        if data_category in [
            "ANALYTICS_PROFILE",
            "PRODUCT_TELEMETRY"
        ]:

            if (
                "still attributable"
                in condition.lower()
            ):

                if state in [
                    "PRESENT",
                    "EXPOSED_PII"
                ]:

                    return {
                        "matched": True,
                        "data_category": data_category,
                        "action": "ANONYMIZE",
                        "condition": condition,
                        "rule_id": rule["rule_id"],
                        "reason": (
                            "Record remains attributable "
                            "to the deletion subject"
                        )
                    }

        # -----------------------------------------------------
        # EMAIL DELIVERY LOG
        # -----------------------------------------------------

        if data_category == "EMAIL_DELIVERY_LOG":

            if (
                "user email address"
                in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "REDACT",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Delivery log contains "
                        "user email information"
                    )
                }

        # -----------------------------------------------------
        # SECURITY AUDIT LOG
        # -----------------------------------------------------

        if data_category == "SECURITY_AUDIT_LOG":

            if (
                "retention period"
                in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "RETAIN",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Security audit record "
                        "falls under retention policy"
                    )
                }

        # -----------------------------------------------------
        # LEGAL HOLD
        # -----------------------------------------------------

        if data_category == "LEGAL_HOLD_RECORD":

            if (
                "legal hold is active"
                in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "RETAIN",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Active legal hold requires "
                        "the record to be retained"
                    )
                }

        # -----------------------------------------------------
        # BACKUP
        # -----------------------------------------------------

        if data_category == "BACKUP_ARCHIVE":

            if (
                "restore access can be blocked"
                in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "RETAIN",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Backup may be retained when "
                        "restore access can be blocked"
                    )
                }

        # -----------------------------------------------------
        # ACCOUNT TOMBSTONE
        # -----------------------------------------------------

        if data_category == "ACCOUNT_TOMBSTONE":

            if (
                "stable internal user_id"
                in condition.lower()
            ):

                return {
                    "matched": True,
                    "data_category": data_category,
                    "action": "REDACT",
                    "condition": condition,
                    "rule_id": rule["rule_id"],
                    "reason": (
                        "Tombstone may preserve the "
                        "stable internal user_id while "
                        "removing personal data"
                    )
                }

        # -----------------------------------------------------
        # NO CONDITION SATISFIED
        # -----------------------------------------------------

        return {
            "matched": True,
            "data_category": data_category,
            "action": None,
            "condition": condition,
            "rule_id": rule["rule_id"],
            "reason": (
                "Policy rule exists but its "
                "condition was not established"
            )
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    engine = PolicyEngine(
        "dataset"
    )

    test_categories = [
        "USER_PROFILE",
        "SEARCH_INDEX_ENTRY",
        "ANALYTICS_PROFILE",
        "SECURITY_AUDIT_LOG",
        "BACKUP_ARCHIVE",
        "ACCOUNT_TOMBSTONE"
    ]

    print(
        "\n========== POLICY ENGINE =========="
    )

    for category in test_categories:

        result = engine.evaluate(
            category,
            "PRESENT"
        )

        print(
            "\nCategory:",
            category
        )

        print(
            "Rule:",
            result["rule_id"]
        )

        print(
            "Action:",
            result["action"]
        )

        print(
            "Reason:",
            result["reason"]
        )