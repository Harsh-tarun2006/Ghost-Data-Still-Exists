import csv
import json
from pathlib import Path


class EvidenceParser:

    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)
        self.evidence_dir = self.dataset_dir / "evidence"
        self.evidence_manifest = self.dataset_dir / "evidence_files.csv"

        self.evidence_files = []
        self.load_manifest()

    def load_manifest(self):

        with open(
            self.evidence_manifest,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)
            self.evidence_files = list(reader)

    def parse_file(self, file_path):

        suffix = file_path.suffix.lower()

        if suffix == ".json":
            return self.parse_json(file_path)

        if suffix in [".log", ".txt", ".sql"]:
            return self.parse_text(file_path)

        if suffix == ".pdf":
            return {
                "format": "pdf",
                "content": None,
                "path": str(file_path)
            }

        if suffix == ".png":
            return {
                "format": "image",
                "content": None,
                "path": str(file_path)
            }

        return {
            "format": "unknown",
            "content": None,
            "path": str(file_path)
        }

    def parse_json(self, file_path):

        try:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                data = json.load(file)

            return {
                "format": "json",
                "content": data,
                "path": str(file_path)
            }

        except Exception as error:

            return {
                "format": "json",
                "content": None,
                "path": str(file_path),
                "error": str(error)
            }

    def parse_text(self, file_path):

        try:

            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            return {
                "format": file_path.suffix.lower().replace(".", ""),
                "content": content,
                "path": str(file_path)
            }

        except Exception as error:

            return {
                "format": file_path.suffix.lower().replace(".", ""),
                "content": None,
                "path": str(file_path),
                "error": str(error)
            }

    def scan_all(self):

        results = []

        for evidence in self.evidence_files:

            file_id = evidence["file_id"]
            relative_path = evidence["file_path"]

            file_path = self.dataset_dir / relative_path

            if not file_path.exists():
                continue

            parsed = self.parse_file(file_path)

            parsed["file_id"] = file_id
            parsed["file_path"] = relative_path
            parsed["origin"] = evidence["origin"]
            parsed["captured_at"] = evidence["captured_at"]

            results.append(parsed)

        return results


if __name__ == "__main__":

    parser = EvidenceParser("dataset")

    results = parser.scan_all()

    print("\n========== EVIDENCE PARSER ==========")

    print("Files parsed:", len(results))

    for item in results[:10]:

        print(
            item["file_id"],
            "|",
            item["format"],
            "|",
            item["file_path"]
        )