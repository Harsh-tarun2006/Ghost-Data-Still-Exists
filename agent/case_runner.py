import csv
from datetime import datetime

from agent.evidence_analyzer import EvidenceAnalyzer
from agent.state_reconstructor import StateReconstructor
from agent.status_engine import StatusEngine
from agent.remediation_planner import RemediationPlanner


class CaseRunner:

    def __init__(self, dataset_dir):

        self.dataset_dir = dataset_dir

        self.analyzer = EvidenceAnalyzer(
            dataset_dir
        )

        self.reconstructor = StateReconstructor(
            dataset_dir
        )

        self.status_engine = StatusEngine()

        self.planner = RemediationPlanner(
            dataset_dir
        )

    # ---------------------------------------------------------
    # Get case
    # ---------------------------------------------------------

    def get_case(self, case_id):

        file_path = (
            f"{self.dataset_dir}/deletion_requests.csv"
        )

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                if row["case_id"] == case_id:
                    return row

        return None

    # ---------------------------------------------------------
    # Validate audit timestamp
    # ---------------------------------------------------------

    def valid_audit_context(self, audit_at):

        if not audit_at:
            return False

        try:

            datetime.fromisoformat(
                audit_at.replace(
                    "Z",
                    "+00:00"
                )
            )

            return True

        except Exception:

            return False

    # ---------------------------------------------------------
    # Run one case
    # ---------------------------------------------------------

    def run(self, case_id):

        case = self.get_case(
            case_id
        )

        if not case:

            return {
                "error": "Case not found"
            }

        email = case["email"]
        audit_at = case["audit_at"]

        # -----------------------------------------------------
        # Check whether audit context exists
        # -----------------------------------------------------

        has_audit_context = (
            self.valid_audit_context(
                audit_at
            )
        )

        # -----------------------------------------------------
        # Evidence analysis
        # -----------------------------------------------------

        analysis = self.analyzer.analyze_user(
            email,
            audit_at
        )

        # -----------------------------------------------------
        # State reconstruction
        # -----------------------------------------------------

        state = self.reconstructor.reconstruct(
            analysis
        )

        # -----------------------------------------------------
        # Status determination
        # -----------------------------------------------------

        status = self.status_engine.determine_status(
            state,
            has_audit_context=has_audit_context
        )

        # -----------------------------------------------------
        # Remediation / verification plan
        # -----------------------------------------------------

        plan = self.planner.build_plan(
            state
        )

        # -----------------------------------------------------
        # Final case result
        # -----------------------------------------------------

        return {

            "case_id": case["case_id"],

            "email": email,

            "audit_at": audit_at,

            "reported_status":
                case["reported_status"],

            "actual_status":
                status,

            "user_id":
                analysis.get("user_id"),

            "state_summary":
                state.get("summary"),

            "steps":
                plan
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    DATASET_DIR = "dataset"

    runner = CaseRunner(
        DATASET_DIR
    )

    result = runner.run(
        "case_33"
    )

    print(
        "\n========== CASE RUNNER =========="
    )

    print(
        f"Case: {result.get('case_id')}"
    )

    print(
        f"Email: {result.get('email')}"
    )

    print(
        f"Audit At: {result.get('audit_at')}"
    )

    print(
        f"User: {result.get('user_id')}"
    )

    print(
        f"Reported: {result.get('reported_status')}"
    )

    print(
        f"Actual: {result.get('actual_status')}"
    )

    print(
        f"State Summary: {result.get('state_summary')}"
    )

    print(
        "\nSteps:"
    )

    for step in result.get(
        "steps",
        []
    ):

        print(step)
