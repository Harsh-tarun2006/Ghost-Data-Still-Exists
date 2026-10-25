from pathlib import Path
from agent.policy_engine import PolicyEngine


class RemediationPlanner:

    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)
        self.policy_engine = PolicyEngine(dataset_dir)

    # =========================================================
    # SYSTEM ID
    # =========================================================

    def extract_system_id(self, state):

        record = str(
            state.get("record", "")
        ).lower()

        system_map = {
            "search_service": "search_service",
            "account_service": "account_service",
            "export_service": "export_service",
            "security_service": "security_service",
            "support_platform": "support_platform",
            "analytics_platform": "analytics_platform",
            "marketing_platform": "marketing_platform",
            "backup_service": "backup_service",
            "notification_service": "notification_service"
        }

        for keyword, system_id in system_map.items():

            if keyword in record:
                return system_id

        return ""

    # =========================================================
    # FINDING OPERATION
    # =========================================================

    def finding_operation(self, state):

        if state == "PRESENT":
            return "REPORT_REMAINING_RECORD"

        if state == "EXPOSED_PII":
            return "REPORT_EXPOSED_PII"

        if state == "RESTORE_RISK":
            return "REPORT_RESTORE_RISK"

        return None

    # =========================================================
    # REMEDIATION OPERATION
    # =========================================================

    def remediation_operation(self, category, state):

     policy = self.policy_engine.evaluate(
        category,
        state
     )

     action = policy.get("action")

    # RETAIN means no remediation is required.
     if action == "RETAIN":
        return None

     if action == "DELETE":
        return "DELETE_RECORD"

     if action == "REDACT":
        return "REDACT_RECORD"

     if action == "ANONYMIZE":
        return "ANONYMIZE_RECORD"

     return None

    # =========================================================
    # VERIFICATION OPERATION
    # =========================================================

    def verification_operation(self, remediation):

        if remediation == "DELETE_RECORD":
            return "VERIFY_RECORD_ABSENT"

        if remediation == "REDACT_RECORD":
            return "VERIFY_RECORD_REDACTED"

        if remediation == "ANONYMIZE_RECORD":
            return "VERIFY_RECORD_ANONYMIZED"

        if remediation == "BLOCK_RESTORE":
            return "VERIFY_RESTORE_BLOCKED"

        if remediation == "DISABLE_DATA_FLOW":
            return "VERIFY_DATA_FLOW_DISABLED"

        return None

    # =========================================================
    # BUILD PLAN
    # =========================================================

    def build_plan(self, state_result):

        if not state_result.get("matched"):
            return []

        findings = state_result.get(
            "states",
            []
        )

        finding_steps = []
        remediation_steps = []
        verification_steps = []

        # =====================================================
        # PASS 1 — FINDINGS
        # =====================================================

        for state in findings:

            operation = self.finding_operation(
                state.get("state")
            )

            if operation is None:
                continue

            resource_ids = state.get(
                "resource_ids",
                []
            )

            resource_id = (
                resource_ids[0]
                if resource_ids
                else ""
            )

            system_id = self.extract_system_id(
                state
            )

            finding_steps.append({

                "phase": "FINDING",

                "system_id":
                    system_id,

                "resource_id":
                    resource_id,

                "operation":
                    operation,

                "state":
                    state.get("state"),

                "evidence_id":
                    state.get("evidence_id")
            })

        # =====================================================
        # PASS 2 — REMEDIATION + VERIFICATION
        # =====================================================

        for state in findings:

            categories = state.get(
                "data_categories",
                []
            )

            resource_ids = state.get(
                "resource_ids",
                []
            )

            resource_id = (
                resource_ids[0]
                if resource_ids
                else ""
            )

            system_id = self.extract_system_id(
                state
            )

            for category in categories:

                remediation = (
                    self.remediation_operation(
                        category,
                        state.get("state")
                    )
                )

                if remediation is None:
                    continue

                # ---------------------------------------------
                # REMEDIATION
                # ---------------------------------------------

                remediation_steps.append({

                    "phase":
                        "REMEDIATION",

                    "system_id":
                        system_id,

                    "resource_id":
                        resource_id,

                    "operation":
                        remediation,

                    "state":
                        state.get("state"),

                    "evidence_id":
                        ""
                })

                # ---------------------------------------------
                # VERIFICATION
                # ---------------------------------------------

                verification = (
                    self.verification_operation(
                        remediation
                    )
                )

                if verification is not None:

                    verification_steps.append({

                        "phase":
                            "VERIFICATION",

                        "system_id":
                            system_id,

                        "resource_id":
                            resource_id,

                        "operation":
                            verification,

                        "state":
                            "EXPECTED",

                        "evidence_id":
                            ""
                    })

        # =====================================================
        # REQUIRED PHASE ORDER
        # FINDING → REMEDIATION → VERIFICATION
        # =====================================================

        steps = (
            finding_steps
            + remediation_steps
            + verification_steps
        )

        # =====================================================
        # STEP NUMBERS
        # =====================================================

        for step_no, step in enumerate(
            steps,
            start=1
        ):

            step["step_no"] = step_no

        return steps


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    from agent.evidence_analyzer import EvidenceAnalyzer
    from agent.state_reconstructor import StateReconstructor

    analyzer = EvidenceAnalyzer(
        "dataset"
    )

    reconstructor = StateReconstructor(
        "dataset"
    )

    planner = RemediationPlanner(
        "dataset"
    )

    analysis = analyzer.analyze_user(
        "ingrid.dahl@outlook.com"
    )

    state = reconstructor.reconstruct(
        analysis
    )

    plan = planner.build_plan(
        state
    )

    print(
        "\n========== REMEDIATION PLAN =========="
    )

    for step in plan:
        print(step)