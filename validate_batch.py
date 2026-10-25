import csv

from agent.case_runner import CaseRunner
from agent.validator import Validator


DATASET_DIR = "dataset"


def main():

    runner = CaseRunner(DATASET_DIR)
    validator = Validator()

    cases_file = "dataset/deletion_requests.csv"

    with open(
        cases_file,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        cases = list(csv.DictReader(f))

    results = []

    for case in cases:

        try:
            result = runner.run(
                case["case_id"]
            )

            results.append(result)

        except Exception as e:

            results.append({
                "case_id": case["case_id"],
                "error": str(e)
            })

    report = validator.validate_batch(
        results
    )

    print()
    print("======================================")
    print("VALIDATION REPORT")
    print("======================================")

    print(
        f"Total cases: {report['total']}"
    )

    print(
        f"Valid cases: {report['valid']}"
    )

    print(
        f"Invalid cases: {report['invalid']}"
    )

    print(
        f"Warnings: {len(report['warnings'])}"
    )

    if report["errors"]:

        print()
        print("VALIDATION ERRORS:")

        for item in report["errors"][:20]:

            print(
                item["case_id"],
                "->",
                item["errors"]
            )

    if report["warnings"]:

        print()
        print("WARNINGS:")

        for item in report["warnings"][:20]:

            print(
                item["case_id"],
                "->",
                item["warnings"]
            )


if __name__ == "__main__":
    main()