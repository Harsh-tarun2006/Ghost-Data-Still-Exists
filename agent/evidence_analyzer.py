import re
from pathlib import Path
from datetime import datetime

from agent.evidence_parser import EvidenceParser
from agent.identity_resolver import IdentityResolver


class EvidenceAnalyzer:

    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)

        self.identity_resolver = IdentityResolver(dataset_dir)
        self.parser = EvidenceParser(dataset_dir)

        self.evidence = self.parser.scan_all()

    # ---------------------------------------------------------
    # BUILD ALL IDENTIFIERS
    # ---------------------------------------------------------

    def build_identifiers(self, identity):

        identifiers = set()

        data = identity.get("identifiers", {})

        for category in [
            "emails",
            "phones",
            "names",
            "email_hashes"
        ]:

            for value in data.get(category, []):

                if value:
                    identifiers.add(
                        str(value).strip().lower()
                    )

        if identity.get("user_id"):
            identifiers.add(
                identity["user_id"].strip().lower()
            )

        return identifiers

    # ---------------------------------------------------------
    # CONVERT CONTENT TO TEXT
    # ---------------------------------------------------------

    def content_to_text(self, content):

        if content is None:
            return ""

        if isinstance(content, str):
            return content.lower()

        if isinstance(content, dict):
            return str(content).lower()

        if isinstance(content, list):
            return str(content).lower()

        return str(content).lower()

    # ---------------------------------------------------------
    # SAFE IDENTIFIER MATCH
    # ---------------------------------------------------------

    def identifier_matches(self, text, identifier):

        text = text.lower()
        identifier = identifier.lower()

        pattern = (
            r"(?<![a-zA-Z0-9_])"
            + re.escape(identifier)
            + r"(?![a-zA-Z0-9_])"
        )

        return re.search(
            pattern,
            text,
            flags=re.IGNORECASE
        ) is not None

    # ---------------------------------------------------------
    # EXTRACT RESOURCE IDS
    # ---------------------------------------------------------

    def identify_resource_ids(self, text):

        resource_ids = set()

        patterns = [

            r'\bresource_id\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)',

            r'\bresourceId\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)',

            r'\b(?:account_id|search_id|cache_id|support_id|'
            r'analytics_id|export_id|marketing_id|backup_id|'
            r'data_flow_id|audit_record_id|tombstone_id)'
            r'\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)'
        ]

        ignored_values = {
            "account_service",
            "search_service",
            "analytics_platform",
            "backup_service",
            "export_service",
            "support_platform",
            "integration_service",
            "security_service",
            "notification_service"
        }

        for pattern in patterns:

            matches = re.findall(
                pattern,
                text,
                flags=re.IGNORECASE
            )

            for match in matches:

                resource_id = match.strip()

                if resource_id.lower() in ignored_values:
                    continue

                resource_ids.add(resource_id)

        return sorted(resource_ids)

    # ---------------------------------------------------------
    # DETECT DATA CATEGORIES
    # ---------------------------------------------------------

    def detect_categories(self, text):

        categories = set()

        category_keywords = {

            "USER_PROFILE": [
                "customer_profiles",
                "user_profile",
                "account_service"
            ],

            "SECONDARY_IDENTIFIER": [
                "secondary_identifier",
                "alternate_identifier"
            ],

            "SEARCH_INDEX_ENTRY": [
                "search_index",
                "search_documents",
                "search_service"
            ],

            "CACHE_ENTRY": [
                "cache_entry",
                "cache_service"
            ],

            "SUPPORT_MESSAGE": [
                "support_conversations",
                "support_message",
                "support_records",
                "support_platform"
            ],

            "SUPPORT_ATTACHMENT": [
                "attachment",
                "attachments"
            ],

            "ANALYTICS_PROFILE": [
                "analytics_profile",
                "analytics_platform",
                "customer_analytics"
            ],

            "PRODUCT_TELEMETRY": [
                "product_telemetry",
                "telemetry"
            ],

            "USER_EXPORT": [
                "customer_export",
                "export_service",
                "export_jobs"
            ],

            "MARKETING_PROFILE": [
                "marketing_profile",
                "marketing_platform"
            ],

            "EMAIL_DELIVERY_LOG": [
                "email_delivery",
                "delivery_log",
                "notification_service"
            ],

            "SECURITY_AUDIT_LOG": [
                "security_audit",
                "audit_record",
                "security_service"
            ],

            "LEGAL_HOLD_RECORD": [
                "legal_hold",
                "legal_service"
            ],

            "BACKUP_ARCHIVE": [
                "backup",
                "backup_archive",
                "backup_service"
            ],

            "ACCOUNT_TOMBSTONE": [
                "tombstone",
                "account_tombstone"
            ]
        }

        for category, keywords in category_keywords.items():

            if any(
                keyword in text
                for keyword in keywords
            ):
                categories.add(category)

        return sorted(categories)

    # ---------------------------------------------------------
    # PARSE DATETIME
    # ---------------------------------------------------------

    def parse_datetime(self, value):

        if not value:
            return None

        try:
            return datetime.fromisoformat(
                str(value).replace(
                    "Z",
                    "+00:00"
                )
            )
        except Exception:
            return None

    # ---------------------------------------------------------
    # EXTRACT EVENT TIME FROM TEXT
    # ---------------------------------------------------------

    def extract_event_time(self, text):

        if not text:
            return None

        # ISO timestamp with Z
        match = re.search(
            r"\b(20\d{2}-\d{2}-\d{2}T"
            r"\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?Z)\b",
            text
        )

        if match:
            return self.parse_datetime(
                match.group(1)
            )

        # ISO timestamp with timezone offset
        match = re.search(
            r"\b(20\d{2}-\d{2}-\d{2}T"
            r"\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?[+-]\d{2}:\d{2})\b",
            text
        )

        if match:
            return self.parse_datetime(
                match.group(1)
            )

        return None

    # ---------------------------------------------------------
    # CHECK EVENT AGAINST AUDIT TIME
    # ---------------------------------------------------------

    def event_is_before_or_at_audit(
        self,
        event_time,
        audit_time
    ):

        # No audit time → cannot filter
        if audit_time is None:
            return True

        # No event timestamp → keep it for now.
        # The evidence itself may still be useful.
        if event_time is None:
            return True

        return event_time <= audit_time

    # ---------------------------------------------------------
    # PARSE RECORD TIMESTAMP
    # ---------------------------------------------------------

    def extract_record_timestamp(
        self,
        record
    ):

        if not isinstance(record, dict):
            return None

        timestamp_keys = [
            "event_time",
            "event_timestamp",
            "timestamp",
            "created_at",
            "updated_at",
            "occurred_at",
            "observed_at",
            "activity_time",
            "activity_at",
            "deleted_at",
            "createdAt",
            "updatedAt",
            "eventTime",
            "eventTimestamp"
        ]

        for key in timestamp_keys:

            if key not in record:
                continue

            value = record.get(key)

            if not value:
                continue

            parsed = self.parse_datetime(
                value
            )

            if parsed:
                return parsed

        return None

    # ---------------------------------------------------------
    # PARSE ONE JSON RECORD
    # ---------------------------------------------------------

    def process_json_record(
        self,
        record,
        evidence,
        identifiers,
        user_id,
        findings,
        audit_time=None,
        context_text=""
    ):

        if not isinstance(record, dict):
            return

        # -----------------------------------------------------
        # EVENT TIME CHECK
        # -----------------------------------------------------

        record_time = self.extract_record_timestamp(
            record
        )

        if not self.event_is_before_or_at_audit(
            record_time,
            audit_time
        ):
            return

        record_text = str(record).lower()

        combined_text = (
            record_text
            + " "
            + context_text.lower()
        )

        matched_identifiers = []

        for identifier in identifiers:

            if self.identifier_matches(
                combined_text,
                identifier
            ):
                matched_identifiers.append(
                    identifier
                )

        if not matched_identifiers:
            return

        resource_ids = self.identify_resource_ids(
            record_text
        )

        categories = self.detect_categories(
            combined_text
        )

        findings.append({

            "evidence_id":
                evidence["file_id"],

            "file_path":
                evidence["file_path"],

            "user_id":
                user_id,

            "matched_identifiers":
                sorted(
                    set(matched_identifiers)
                ),

            "resource_ids":
                resource_ids,

            "data_categories":
                categories,

            "record":
                record,

            "event_time":
                record_time.isoformat()
                if record_time
                else None
        })

    # ---------------------------------------------------------
    # RECURSIVELY PROCESS JSON
    # ---------------------------------------------------------

    def process_json_structure(
        self,
        obj,
        evidence,
        identifiers,
        user_id,
        findings,
        audit_time=None,
        context=None
    ):

        if context is None:
            context = []

        # -----------------------------------------------------
        # DICTIONARY
        # -----------------------------------------------------

        if isinstance(obj, dict):

            local_context = list(context)

            metadata_keys = [
                "data_store",
                "collection",
                "service",
                "system",
                "source",
                "record_type",
                "section",
                "category"
            ]

            for key in metadata_keys:

                if key in obj:

                    value = obj[key]

                    if isinstance(
                        value,
                        (str, int, float, bool)
                    ):

                        local_context.append(
                            str(value)
                        )

            # Keys that indicate an actual record.
            record_keys = {

                "resource_id",
                "user_id",
                "customer_id",
                "customer_reference",
                "subject_reference",

                "email",
                "owner_email",
                "customer_email",
                "requester_email",

                "record_id",
                "profile_id",
                "account_id",
                "search_id",
                "support_id",
                "analytics_id",
                "export_id",
                "marketing_id",
                "audit_record_id",
                "tombstone_id"
            }

            looks_like_record = any(
                key in obj
                for key in record_keys
            )

            # -------------------------------------------------
            # ACTUAL RECORD
            # -------------------------------------------------

            if looks_like_record:

                self.process_json_record(
                    obj,
                    evidence,
                    identifiers,
                    user_id,
                    findings,
                    audit_time,
                    " ".join(local_context)
                )

                return

            # -------------------------------------------------
            # OTHERWISE RECURSE
            # -------------------------------------------------

            for key, value in obj.items():

                child_context = list(
                    local_context
                )

                child_context.append(
                    str(key)
                )

                self.process_json_structure(
                    value,
                    evidence,
                    identifiers,
                    user_id,
                    findings,
                    audit_time,
                    child_context
                )

        # -----------------------------------------------------
        # LIST
        # -----------------------------------------------------

        elif isinstance(obj, list):

            for item in obj:

                self.process_json_structure(
                    item,
                    evidence,
                    identifiers,
                    user_id,
                    findings,
                    audit_time,
                    context
                )

    # ---------------------------------------------------------
    # ADD TEXT FINDING
    # ---------------------------------------------------------

    def process_text_line(
        self,
        line,
        evidence,
        identifiers,
        user_id,
        findings,
        audit_time
    ):

        if not line:
            return

        # -----------------------------------------------------
        # EVENT TIME
        # -----------------------------------------------------

        event_time = self.extract_event_time(
            line
        )

        # Ignore events that happened after audit.
        if not self.event_is_before_or_at_audit(
            event_time,
            audit_time
        ):
            return

        line_lower = line.lower()

        matched_identifiers = []

        for identifier in identifiers:

            if self.identifier_matches(
                line_lower,
                identifier
            ):

                matched_identifiers.append(
                    identifier
                )

        if not matched_identifiers:
            return

        resource_ids = self.identify_resource_ids(
            line_lower
        )

        categories = self.detect_categories(
            line_lower
        )

        findings.append({

            "evidence_id":
                evidence["file_id"],

            "file_path":
                evidence["file_path"],

            "user_id":
                user_id,

            "matched_identifiers":
                sorted(
                    set(matched_identifiers)
                ),

            "resource_ids":
                resource_ids,

            "data_categories":
                categories,

            "record":
                line.strip(),

            "event_time":
                event_time.isoformat()
                if event_time
                else None
        })

    # ---------------------------------------------------------
    # MAIN ANALYSIS
    # ---------------------------------------------------------

    def analyze_user(
        self,
        email,
        audit_at=None
    ):

        identity = self.identity_resolver.resolve(
            email
        )

        if not identity["matched"]:

            return {

                "matched": False,

                "user_id": None,

                "identifiers": {},

                "audit_at":
                    audit_at,

                "findings": []
            }

        identifiers = self.build_identifiers(
            identity
        )

        findings = []

        # Convert audit_at once.
        audit_time = self.parse_datetime(
            audit_at
        )

        # -----------------------------------------------------
        # SCAN ALL EVIDENCE
        # -----------------------------------------------------

        for evidence in self.evidence:

            content = evidence.get(
                "content"
            )

            if not content:
                continue

            evidence_format = evidence.get(
                "format"
            )

            # -------------------------------------------------
            # LOG / TXT
            # -------------------------------------------------

            if evidence_format in [
                "log",
                "txt",
                "sql"
            ]:

                lines = content.splitlines()

                for line in lines:

                    self.process_text_line(
                        line,
                        evidence,
                        identifiers,
                        identity["user_id"],
                        findings,
                        audit_time
                    )

            # -------------------------------------------------
            # JSON
            # -------------------------------------------------

            elif evidence_format == "json":

                self.process_json_structure(
                    content,
                    evidence,
                    identifiers,
                    identity["user_id"],
                    findings,
                    audit_time
                )

        # -----------------------------------------------------
        # REMOVE EXACT DUPLICATES
        # -----------------------------------------------------
        
            seen = set()
        unique_findings = []

        for finding in findings:

         key = (
        finding.get("evidence_id"),
        str(finding.get("record")),
        tuple(
            str(x)
            for x in finding.get("resource_ids", [])
         )
              )

         if key in seen:
        
           continue
       

           seen.add(key)

         unique_findings.append(
         finding
          )

        findings = unique_findings

        # -----------------------------------------------------
        # SORT FINDINGS
        # -----------------------------------------------------

        findings.sort(
            key=lambda item: (
                item.get("event_time") or "",
                item.get("evidence_id") or "",
                str(
                    item.get("record") or ""
                )
            )
        )

        # -----------------------------------------------------
        # FINAL RESULT
        # -----------------------------------------------------

        return {

            "matched": True,

            "user_id":
                identity["user_id"],

            "identifiers":
                identity["identifiers"],

            "audit_at":
                audit_at,

            "findings":
                findings
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    analyzer = EvidenceAnalyzer(
        "dataset"
    )

    test_email = (
        "ingrid.dahl@outlook.com"
    )

    test_audit_at = (
        "2026-07-19T13:00:00Z"
    )

    result = analyzer.analyze_user(
        test_email,
        test_audit_at
    )

    print(
        "\n========== EVIDENCE ANALYZER =========="
    )

    print(
        "Matched:",
        result["matched"]
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
        "Identifiers:",
        result["identifiers"]
    )

    print(
        "Findings:",
        len(result["findings"])
    )

    for finding in result["findings"]:

        print(
            "\n-----------------------------------"
        )

        print(
            "Evidence:",
            finding["evidence_id"]
        )

        print(
            "File:",
            finding["file_path"]
        )

        print(
            "Event Time:",
            finding.get("event_time")
        )

        print(
            "Identifiers:",
            finding["matched_identifiers"]
        )

        print(
            "Resources:",
            finding["resource_ids"]
        )

        print(
            "Categories:",
            finding["data_categories"]
        )

        print(
            "Record:",
            finding["record"]
        )