import csv
from pathlib import Path


class IdentityResolver:

    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)

        self.users = []
        self.audit_logs = []

        self.load_users()
        self.load_audit_logs()

    def load_users(self):
        file_path = self.dataset_dir / "user_identities.csv"

        with open(file_path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            self.users = list(reader)

    def load_audit_logs(self):
        file_path = self.dataset_dir / "user_audit_log.csv"

        with open(file_path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            self.audit_logs = list(reader)

    def resolve(self, email):

        email = email.strip().lower()

              # Find current user by current email
        user = next(
            (
                user
                for user in self.users
                if user["email"].strip().lower() == email
            ),
            None
        )

        # If current email is not found, search historical audit logs
        user_id = None

        if user:
            user_id = user["user_id"]
        else:
            historical_match = next(
                (
                    log
                    for log in self.audit_logs
                    if log["field_name"] == "email"
                    and (
                        log["old_value"].strip().lower() == email
                        or log["new_value"].strip().lower() == email
                    )
                ),
                None
            )

            if historical_match:
                user_id = historical_match["user_id"]

                # Recover the current user record
                user = next(
                    (
                        user
                        for user in self.users
                        if user["user_id"] == user_id
                    ),
                    None
                )

        # No current or historical match
        if not user or not user_id:
            return {
                "matched": False,
                "user_id": None,
                "identifiers": [],
                "reason": "No current or historical email match found"
            }
        user_id = user["user_id"]

        # Current identifiers
        identifiers = {
            "emails": set(),
            "phones": set(),
            "names": set(),
            "email_hashes": set()
        }

        if user["email"]:
            identifiers["emails"].add(
                user["email"].strip().lower()
            )

        if user["phone"]:
            identifiers["phones"].add(user["phone"])

        if user["name"]:
            identifiers["names"].add(user["name"])

        if user["email_hash"]:
            identifiers["email_hashes"].add(user["email_hash"])

        # Find historical changes
        historical_changes = [
            log
            for log in self.audit_logs
            if log["user_id"] == user_id
        ]

        # Add historical identifiers
        for log in historical_changes:

            field = log["field_name"]

            if field == "email":

                if log["old_value"]:
                    identifiers["emails"].add(
                        log["old_value"].strip().lower()
                    )

                if log["new_value"]:
                    identifiers["emails"].add(
                        log["new_value"].strip().lower()
                    )

            elif field == "phone":

                if log["old_value"]:
                    identifiers["phones"].add(
                        log["old_value"]
                    )

                if log["new_value"]:
                    identifiers["phones"].add(
                        log["new_value"]
                    )

            elif field == "name":

                if log["old_value"]:
                    identifiers["names"].add(
                        log["old_value"]
                    )

                if log["new_value"]:
                    identifiers["names"].add(
                        log["new_value"]
                    )

            elif field == "email_hash":

                if log["old_value"]:
                    identifiers["email_hashes"].add(
                        log["old_value"]
                    )

                if log["new_value"]:
                    identifiers["email_hashes"].add(
                        log["new_value"]
                    )

        return {
            "matched": True,
            "user_id": user_id,
            "identifiers": {
                "emails": sorted(identifiers["emails"]),
                "phones": sorted(identifiers["phones"]),
                "names": sorted(identifiers["names"]),
                "email_hashes": sorted(identifiers["email_hashes"])
            },
            "historical_changes": historical_changes,
            "reason": "Identity resolved successfully"
        }


if __name__ == "__main__":

    resolver = IdentityResolver("dataset")

    result = resolver.resolve("amina.elmasri@gmail.com")

    print(result)