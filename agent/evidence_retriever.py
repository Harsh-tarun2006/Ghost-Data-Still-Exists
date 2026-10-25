import csv
import re
from datetime import datetime
from pathlib import Path


class EvidenceRetriever:

    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)

        self.system_activity = []
        self.evidence_files = []
        self.resource_identity_map = {}

        self.load_system_activity()
        self.load_evidence_files()
        self.build_identity_map()

    # ---------------------------------------------------------
    # DATETIME
    # ---------------------------------------------------------

    def parse_datetime(self, value):

        if not value:
            return None

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except Exception:
            return None

    # ---------------------------------------------------------
    # LOAD SYSTEM ACTIVITY
    # ---------------------------------------------------------

    def load_system_activity(self):

        file_path = self.dataset_dir / "system_activity.csv"

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            self.system_activity = list(reader)

    # ---------------------------------------------------------
    # LOAD EVIDENCE MANIFEST
    # ---------------------------------------------------------

    def load_evidence_files(self):

        file_path = self.dataset_dir / "evidence_files.csv"

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            self.evidence_files = list(reader)

    # ---------------------------------------------------------
    # BUILD IDENTITY MAP
    # ---------------------------------------------------------

    def build_identity_map(self):

        for activity in self.system_activity:

            if activity["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue

            details = activity["details"]

            resource_id = activity["resource_id"]

            match = re.search(
                r"to\s+(\S+)\s+and\s+(user_\d+)",
                details
            )

            if not match:
                continue

            email = match.group(1).strip().lower()

            user_id = match.group(2)

            if user_id not in self.resource_identity_map:

                self.resource_identity_map[user_id] = []

            self.resource_identity_map[user_id].append({

                "resource_id":
                    resource_id,

                "email":
                    email,

                "target_system":
                    activity["target_system"],

                "activity_id":
                    activity["activity_id"],

                "event_time":
                    activity["event_time"]
            })

    # ---------------------------------------------------------
    # GET IDENTITY LINKS AT AUDIT TIME
    # ---------------------------------------------------------

    def get_historical_links(
        self,
        user_id,
        audit_at=None
    ):

        links = self.resource_identity_map.get(
            user_id,
            []
        )

        if not audit_at:
            return links

        audit_time = self.parse_datetime(
            audit_at
        )

        if audit_time is None:
            return links

        valid_links = []

        for link in links:

            event_time = self.parse_datetime(
                link["event_time"]
            )

            if event_time is None:
                continue

            if event_time <= audit_time:
                valid_links.append(link)

        return valid_links

    # ---------------------------------------------------------
    # RETRIEVE USER ACTIVITIES
    # ---------------------------------------------------------

    def retrieve_for_user(
        self,
        user_id,
        audit_at=None
    ):

        linked_resources = self.get_historical_links(
            user_id,
            audit_at
        )

        resource_ids = {
            item["resource_id"]
            for item in linked_resources
        }

        audit_time = None

        if audit_at:
            audit_time = self.parse_datetime(
                audit_at
            )

        related_activities = []

        for activity in self.system_activity:

            if activity["resource_id"] not in resource_ids:
                continue

            if audit_time:

                event_time = self.parse_datetime(
                    activity["event_time"]
                )

                if event_time is not None:

                    if event_time > audit_time:
                        continue

            related_activities.append(
                activity
            )

        return {

            "user_id":
                user_id,

            "audit_at":
                audit_at,

            "linked_resources":
                linked_resources,

            "resource_ids":
                sorted(resource_ids),

            "activities":
                related_activities
        }

    # ---------------------------------------------------------
    # FIND EVIDENCE CANDIDATES
    # ---------------------------------------------------------

    def find_evidence_candidates(
        self,
        user_id,
        audit_at=None
    ):

        result = self.retrieve_for_user(
            user_id,
            audit_at
        )

        resource_ids = result[
            "resource_ids"
        ]

        identifiers = {
            item["email"]
            for item in result[
                "linked_resources"
            ]
        }

        candidates = []

        evidence_dir = (
            self.dataset_dir / "evidence"
        )

        if not evidence_dir.exists():

            print(
                "\nWARNING: evidence directory not found:"
            )

            print(evidence_dir)

            return candidates

        for evidence in self.evidence_files:

            relative_path = evidence[
                "file_path"
            ]

            file_path = (
                self.dataset_dir
                / relative_path
            )

            if not file_path.exists():
                continue

            path_text = relative_path.lower()

            path_match = any(
                resource.lower()
                in path_text
                for resource in resource_ids
            )

            text_match = False

            suffix = file_path.suffix.lower()

            if suffix in [
                ".log",
                ".txt",
                ".json",
                ".sql"
            ]:

                try:

                    content = file_path.read_text(
                        encoding="utf-8",
                        errors="ignore"
                    ).lower()

                    for resource in resource_ids:

                        if resource.lower() in content:

                            text_match = True
                            break

                    if not text_match:

                        for identifier in identifiers:

                            if identifier in content:

                                text_match = True
                                break

                except Exception:
                    pass

            if path_match or text_match:

                candidates.append({

                    "file_id":
                        evidence["file_id"],

                    "file_path":
                        evidence["file_path"],

                    "origin":
                        evidence["origin"],

                    "captured_at":
                        evidence["captured_at"],

                    "path_match":
                        path_match,

                    "content_match":
                        text_match
                })

        return candidates


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    retriever = EvidenceRetriever(
        "dataset"
    )

    user_id = "user_18"

    audit_at = (
        "2026-07-19T13:00:00Z"
    )

    print(
        "\n========== HISTORICAL USER RETRIEVAL =========="
    )

    result = retriever.retrieve_for_user(
        user_id,
        audit_at
    )

    print(
        "User ID:",
        result["user_id"]
    )

    print(
        "Audit At:",
        result["audit_at"]
    )

    print(
        "Resources:",
        result["resource_ids"]
    )

    print(
        "\nIdentity Links:"
    )

    for link in result["linked_resources"]:

        print(
            link
        )

    print(
        "\nActivities:"
    )

    for activity in result["activities"]:

        print(
            activity["activity_id"],
            "|",
            activity["event_time"],
            "|",
            activity["event_type"],
            "|",
            activity["resource_id"],
            "|",
            activity["reported_result"]
        )

    print(
        "\n========== EVIDENCE CANDIDATES =========="
    )

    candidates = (
        retriever.find_evidence_candidates(
            user_id,
            audit_at
        )
    )

    print(
        "Candidate evidence:",
        len(candidates)
    )

    for evidence in candidates:

        print(evidence)