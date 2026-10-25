class StatusEngine:

    # States that directly mean deletion is incomplete.
    BLOCKING_STATES = {
        "PRESENT",
        "EXPOSED_PII",
        "RESTORE_RISK"
    }

    # These states are observations, not proof of remaining data.
    NON_BLOCKING_STATES = {
        "OBSERVATION",
        "IDENTITY_LINK",
        "RETAINED"
    }

    def determine_status(
        self,
        state_result,
        has_audit_context=False
    ):

        # -----------------------------------------------------
        # Identity / case could not be resolved
        # -----------------------------------------------------

        if not state_result.get("matched"):

            return "INCOMPLETE"

        states = state_result.get(
            "states",
            []
        )

        # -----------------------------------------------------
        # Any direct remaining-data/risk finding
        # -----------------------------------------------------

        for item in states:

            state = item.get(
                "state"
            )

            if state in self.BLOCKING_STATES:
                return "INCOMPLETE"

        # -----------------------------------------------------
        # Unknown state is not safe to call COMPLETE
        # -----------------------------------------------------

        for item in states:

            if item.get("state") == "UNKNOWN":
                return "INCOMPLETE"

        # -----------------------------------------------------
        # No findings
        #
        # IMPORTANT:
        # Zero findings alone does NOT prove deletion.
        # -----------------------------------------------------

        if not states:

            if not has_audit_context:
                return "INCOMPLETE"

            # With a valid audit context and no contradictory
            # evidence, the case can be considered complete.
            return "COMPLETE"

        # -----------------------------------------------------
        # Only observations / retained records
        # -----------------------------------------------------

        return "COMPLETE"


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    engine = StatusEngine()

    test_cases = {

        "complete_with_retention": {
            "matched": True,
            "states": [
                {
                    "state": "RETAINED"
                }
            ]
        },

        "remaining_record": {
            "matched": True,
            "states": [
                {
                    "state": "PRESENT"
                }
            ]
        },

        "exposed_pii": {
            "matched": True,
            "states": [
                {
                    "state": "EXPOSED_PII"
                }
            ]
        },

        "restore_risk": {
            "matched": True,
            "states": [
                {
                    "state": "RESTORE_RISK"
                }
            ]
        },

        "observation_only": {
            "matched": True,
            "states": [
                {
                    "state": "OBSERVATION"
                }
            ]
        },

        "identity_only": {
            "matched": True,
            "states": [
                {
                    "state": "IDENTITY_LINK"
                }
            ]
        },

        "unknown": {
            "matched": True,
            "states": [
                {
                    "state": "UNKNOWN"
                }
            ]
        },

        "zero_findings": {
            "matched": True,
            "states": []
        }
    }

    print(
        "\n========== STATUS ENGINE TEST =========="
    )

    for name, state_result in test_cases.items():

        status = engine.determine_status(
            state_result,
            has_audit_context=True
        )

        print(
            f"{name:25} -> {status}"
        )