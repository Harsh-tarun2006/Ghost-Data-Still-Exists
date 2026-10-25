import csv
from pathlib import Path

from agent.case_runner import CaseRunner


DATASET_DIR = "dataset"
OUTPUT_FILE = "output.csv"


def main():

    runner = CaseRunner(DATASET_DIR)

    cases_file = Path(DATASET_DIR) / "deletion_requests.csv"

    results = []

    with open(
        cases_file,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        cases = list(reader)

    print(f"Total cases found: {len(cases)}")

    for index, case in enumerate(cases, start=1):

        case_id = case["case_id"]

        try:

            result = runner.run(case_id)

            results.append({
                "case_id": case_id,
                "email": result.get("email", ""),
                "audit_at": result.get("audit_at", ""),
                "reported_status": result.get(
                    "reported_status",
                    ""
                ),
                "actual_status": result.get(
                    "actual_status",
                    ""
                ),
                "user_id": result.get(
                    "user_id",
                    ""
                ),
                "present": result.get(
                    "state_summary", {}
                ).get("present", 0),
                "observation": result.get(
                    "state_summary", {}
                ).get("observation", 0),
                "exposed_pii": result.get(
                    "state_summary", {}
                ).get("exposed_pii", 0),
                "retained": result.get(
                    "state_summary", {}
                ).get("retained", 0),
                "restore_risk": result.get(
                    "state_summary", {}
                ).get("restore_risk", 0),
                "identity_link": result.get(
                    "state_summary", {}
                ).get("identity_link", 0),
                "unknown": result.get(
                    "state_summary", {}
                ).get("unknown", 0),
                "step_count": len(
                    result.get("steps", [])
                )
            })

            print(
                f"[{index}/{len(cases)}] "
                f"{case_id} -> "
                f"{result.get('actual_status')}"
            )

        except Exception as e:

            print(
                f"[{index}/{len(cases)}] "
                f"{case_id} -> ERROR: {e}"
            )

            results.append({
                "case_id": case_id,
                "email": case.get("email", ""),
                "audit_at": case.get("audit_at", ""),
                "reported_status": case.get(
                    "status", ""
                ),
                "actual_status": "ERROR",
                "user_id": "",
                "present": 0,
                "observation": 0,
                "exposed_pii": 0,
                "retained": 0,
                "restore_risk": 0,
                "identity_link": 0,
                "unknown": 0,
                "step_count": 0
            })

    fieldnames = [
        "case_id",
        "email",
        "audit_at",
        "reported_status",
        "actual_status",
        "user_id",
        "present",
        "observation",
        "exposed_pii",
        "retained",
        "restore_risk",
        "identity_link",
        "unknown",
        "step_count"
    ]

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print()
    print("======================================")
    print("BATCH PROCESSING COMPLETE")
    print("======================================")
    print(f"Cases processed: {len(results)}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()