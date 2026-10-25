class Validator:

    BLOCKING_STATES = {
        "PRESENT",
        "EXPOSED_PII",
        "RESTORE_RISK"
    }

    VALID_STATES = {
        "PRESENT",
        "OBSERVATION",
        "EXPOSED_PII",
        "RETAINED",
        "RESTORE_RISK",
        "IDENTITY_LINK",
        "UNKNOWN"
    }

    VALID_STATUSES = {
        "COMPLETE",
        "INCOMPLETE"
    }

    def validate_case(self, result):

        errors = []
        warnings = []

        # -----------------------------------------------------
        # Required fields
        # -----------------------------------------------------

        required_fields = [
            "case_id",
            "email",
            "audit_at",
            "actual_status",
            "state_summary",
            "steps"
        ]

        for field in required_fields:

            if field not in result:
                errors.append(
                    f"Missing required field: {field}"
                )

        if errors:
            return {
                "valid": False,
                "errors": errors,
                "warnings": warnings
            }

        # -----------------------------------------------------
        # Validate status
        # -----------------------------------------------------

        actual_status = result.get(
            "actual_status"
        )

        if actual_status not in self.VALID_STATUSES:

            errors.append(
                f"Invalid actual_status: {actual_status}"
            )

        # -----------------------------------------------------
        # Validate state summary
        # -----------------------------------------------------

        summary = result.get(
            "state_summary"
        ) or {}

        summary_fields = [
            "present",
            "observation",
            "exposed_pii",
            "retained",
            "restore_risk",
            "identity_link",
            "unknown"
        ]

        for field in summary_fields:

            value = summary.get(
                field,
                0
            )

            if not isinstance(value, int):

                errors.append(
                    f"State count '{field}' is not an integer"
                )

            elif value < 0:

                errors.append(
                    f"State count '{field}' is negative"
                )

        # -----------------------------------------------------
        # Check whether blocking states exist
        # -----------------------------------------------------

        blocking_count = (
            summary.get("present", 0)
            + summary.get("exposed_pii", 0)
            + summary.get("restore_risk", 0)
        )

        unknown_count = summary.get(
            "unknown",
            0
        )

        # -----------------------------------------------------
        # Status consistency
        # -----------------------------------------------------

        if actual_status == "COMPLETE":

            if blocking_count > 0:

                errors.append(
                    "Case is COMPLETE but contains blocking states"
                )

            if unknown_count > 0:

                errors.append(
                    "Case is COMPLETE but contains UNKNOWN states"
                )

        if actual_status == "INCOMPLETE":

            if blocking_count == 0 and unknown_count == 0:

                warnings.append(
                    "Case is INCOMPLETE but has no blocking or UNKNOWN states"
                )

        # -----------------------------------------------------
        # Validate steps
        # -----------------------------------------------------

        steps = result.get(
            "steps"
        ) or []

        if not isinstance(steps, list):

            errors.append(
                "Steps must be a list"
            )

        else:

            expected_step_no = 1

            for step in steps:

                if not isinstance(step, dict):

                    errors.append(
                        "Invalid remediation step format"
                    )

                    continue

                step_no = step.get(
                    "step_no"
                )

                if step_no != expected_step_no:

                    errors.append(
                        f"Invalid step numbering: expected "
                        f"{expected_step_no}, got {step_no}"
                    )

                expected_step_no += 1

                operation = step.get(
                    "operation"
                )

                if not operation:

                    errors.append(
                        f"Step {step_no} has no operation"
                    )

                phase = step.get(
                    "phase"
                )

                if phase not in {
                    "FINDING",
                    "REMEDIATION",
                    "VERIFICATION"
                }:

                    errors.append(
                        f"Step {step_no} has invalid phase: {phase}"
                    )

        # -----------------------------------------------------
        # Validate identifiers
        # -----------------------------------------------------

        if not result.get("case_id"):

            errors.append(
                "Missing case_id"
            )

        if not result.get("email"):

            errors.append(
                "Missing email"
            )

        if not result.get("audit_at"):

            errors.append(
                "Missing audit_at"
            )

        # -----------------------------------------------------
        # Final result
        # -----------------------------------------------------

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }

    def validate_batch(self, results):

        total = len(results)
        valid = 0
        invalid = 0

        errors = []
        warnings = []

        for result in results:

            validation = self.validate_case(
                result
            )

            if validation["valid"]:
                valid += 1
            else:
                invalid += 1

                errors.append({
                    "case_id": result.get("case_id"),
                    "errors": validation["errors"]
                })

            if validation["warnings"]:

                warnings.append({
                    "case_id": result.get("case_id"),
                    "warnings": validation["warnings"]
                })

        return {
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "errors": errors,
            "warnings": warnings
        }


if __name__ == "__main__":

    validator = Validator()

    test_result = {
        "case_id": "test",
        "email": "test@example.com",
        "audit_at": "2026-01-01T00:00:00Z",
        "actual_status": "COMPLETE",
        "state_summary": {
            "present": 0,
            "observation": 1,
            "exposed_pii": 0,
            "retained": 1,
            "restore_risk": 0,
            "identity_link": 0,
            "unknown": 0
        },
        "steps": []
    }

    print(
        validator.validate_case(
            test_result
        )
    )