from pathlib import Path


class StateReconstructor:

    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)

    def determine_state(self, finding):
        record = str(finding.get("record", "")).upper()
        categories = finding.get("data_categories", [])

        # ---------------------------------------------------------
        # Explicit non-blocking states
        # ---------------------------------------------------------

        # Data flow is already disabled.
        if "DATA_FLOW" in record and "DISABLED" in record:
            return "OBSERVATION"

        # Backup restoration is already blocked.
        if "BACKUP_ARCHIVE" in categories and "BLOCKED" in record:
            return "RETAINED"

        # Support message has already been redacted.
        if "SUPPORT_MESSAGE" in categories and "REDACTED" in record:
            return "OBSERVATION"

        # ---------------------------------------------------------
        # Existing state rules
        # ---------------------------------------------------------
        if "DATA_FLOW" in record:
            return "OBSERVATION"
        if "CONNECTOR_CONFIG_READ_STARTED" in record:
            return "OBSERVATION"
        if "LINK_RESOURCE_IDENTITY" in record:
            return "IDENTITY_LINK"

        if "SEARCH_INDEX_ENTRY" in categories:
                return "PRESENT"

        if "USER_PROFILE" in categories:
            return "OBSERVATION"

        if "USER_EXPORT" in categories:
            return "OBSERVATION"

        if "SECURITY_AUDIT_LOG" in categories:
            return "RETAINED"

        if "SUPPORT_MESSAGE" in categories:
            return "PRESENT"

        if "SUPPORT_ATTACHMENT" in categories:
            return "PRESENT"

        if "ANALYTICS_PROFILE" in categories:
            pii_indicators = [
                "@",
                "EMAIL",
                "PHONE",
                "ADDRESS",
                "NAME"
            ]

            if any(indicator in record for indicator in pii_indicators):
                return "EXPOSED_PII"

            return "PRESENT"

        if "PRODUCT_TELEMETRY" in categories:
            return "PRESENT"

        if "MARKETING_PROFILE" in categories:
            return "PRESENT"

        if "EMAIL_DELIVERY_LOG" in categories:
            return "PRESENT"

        if "LEGAL_HOLD_RECORD" in categories:
            return "RETAINED"

        if "BACKUP_ARCHIVE" in categories:
            return "RESTORE_RISK"

        if "ACCOUNT_TOMBSTONE" in categories:
            return "PRESENT"

        return "UNKNOWN"

    def reconstruct(self, analysis):
        if not analysis.get("matched"):
            return {
                "matched": False,
                "states": [],
                "summary": {
                    "present": 0,
                    "observation": 0,
                    "exposed_pii": 0,
                    "retained": 0,
                    "restore_risk": 0,
                    "identity_link": 0,
                    "unknown": 0
                }
            }

        states = []

        for finding in analysis.get("findings", []):
            state = self.determine_state(finding)

            state_item = {
                "evidence_id": finding.get("evidence_id", ""),
                "file_path": finding.get("file_path", ""),
                "user_id": finding.get("user_id", ""),
                "resource_ids": finding.get("resource_ids", []),
                "data_categories": finding.get("data_categories", []),
                "state": state,
                "reason": self.state_reason(state, finding),
                "record": finding.get("record", "")
            }

            states.append(state_item)

        summary = {
            "present": 0,
            "observation": 0,
            "exposed_pii": 0,
            "retained": 0,
            "restore_risk": 0,
            "identity_link": 0,
            "unknown": 0
        }

        for item in states:
            state = item.get("state", "UNKNOWN")

            if state == "PRESENT":
                summary["present"] += 1

            elif state == "OBSERVATION":
                summary["observation"] += 1

            elif state == "EXPOSED_PII":
                summary["exposed_pii"] += 1

            elif state == "RETAINED":
                summary["retained"] += 1

            elif state == "RESTORE_RISK":
                summary["restore_risk"] += 1

            elif state == "IDENTITY_LINK":
                summary["identity_link"] += 1

            else:
                summary["unknown"] += 1

        return {
            "matched": True,
            "states": states,
            "summary": summary
        }

    def state_reason(self, state, finding):
        categories = finding.get("data_categories", [])
        record = str(finding.get("record", "")).upper()

        if state == "PRESENT":
            if "SEARCH_INDEX_ENTRY" in categories:
                return "A matching search-index record was detected."

            if "SUPPORT_MESSAGE" in categories:
                return "A support message record was detected."

            if "SUPPORT_ATTACHMENT" in categories:
                return "A support attachment record was detected."

            if "PRODUCT_TELEMETRY" in categories:
                return "Product telemetry associated with the user was detected."

            if "MARKETING_PROFILE" in categories:
                return "A marketing profile associated with the user was detected."

            if "EMAIL_DELIVERY_LOG" in categories:
                return "An email delivery record associated with the user was detected."

            if "ACCOUNT_TOMBSTONE" in categories:
                return "An account tombstone record was detected."

            return "A matching record was detected."

        if state == "OBSERVATION":
            if "USER_PROFILE" in categories:
                return (
                    "A profile lookup was observed, but this does not prove "
                    "that the user profile still exists."
                )

            if "USER_EXPORT" in categories:
                return (
                    "An export-related activity was observed, but this does not "
                    "by itself prove that a retained export record existed at audit time."
                )

            if "DATA_FLOW" in record and "DISABLED" in record:
                return "The data flow was already disabled."

            if "SUPPORT_MESSAGE" in categories and "REDACTED" in record:
                return "The support message was already redacted."

            return "The activity is observational and does not prove remaining data."

        if state == "EXPOSED_PII":
            return "PII associated with the user remains exposed."

        if state == "RETAINED":
            if "BACKUP_ARCHIVE" in categories:
                return "Backup restoration is blocked or retained under policy."

            if "SECURITY_AUDIT_LOG" in categories:
                return "Security audit activity was detected and may be retained by policy."

            if "LEGAL_HOLD_RECORD" in categories:
                return "The record is retained because of a legal hold."

            return "The record may be retained under policy."

        if state == "RESTORE_RISK":
            return "Backup archive may allow restoration of deleted data."

        if state == "IDENTITY_LINK":
            return "The record links an internal resource to the user's identity."

        return "No deterministic state rule matched this finding."


if __name__ == "__main__":
    reconstructor = StateReconstructor("dataset")
    print("StateReconstructor loaded successfully.")