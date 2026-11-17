import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List

from backend.app.core.config import settings
from backend.app.core.database import db_manager, utc_now_iso
from backend.app.core.security import compute_sha256_file


def verify_dataset_integrity(dataset_id: str) -> Dict[str, Any]:
    """
    Recalculates the SHA-256 digest of the preserved raw file on disk and compares
    it against the immutable provenance record stored upon ingestion.
    """
    with db_manager.connection() as conn:
        f_row = conn.execute(
            "SELECT * FROM dataset_files WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()
        m_row = conn.execute(
            "SELECT * FROM source_manifest WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()
        if not f_row or not m_row:
            raise ValueError(f"Provenance record for dataset '{dataset_id}' not found.")

        raw_path = Path(f_row["stored_raw_path"])
        now_iso = utc_now_iso()
        if not raw_path.exists():
            status = "MISSING_RAW_FILE"
            recalculated = None
            matches = False
        else:
            recalculated = compute_sha256_file(raw_path)
            matches = recalculated == m_row["sha256_checksum"]
            status = "VERIFIED" if matches else "INTEGRITY_MISMATCH"

        conn.execute(
            "UPDATE source_manifest SET last_verified_at = ?, integrity_status = ? WHERE dataset_id = ?",
            (now_iso, status, dataset_id),
        )

    db_manager.log_audit(
        actor="researcher",
        action_type="PROVENANCE_INTEGRITY_CHECK",
        entity_type="dataset",
        entity_id=dataset_id,
        details={
            "expected_sha256": m_row["sha256_checksum"],
            "recalculated_sha256": recalculated,
            "integrity_status": status,
        },
    )

    return {
        "dataset_id": dataset_id,
        "original_filename": m_row["original_filename"],
        "expected_sha256": m_row["sha256_checksum"],
        "recalculated_sha256": recalculated,
        "integrity_verified": matches,
        "integrity_status": status,
        "verified_at": now_iso,
    }


def list_provenance_records() -> List[Dict[str, Any]]:
    with db_manager.connection() as conn:
        rows = conn.execute(
            "SELECT * FROM source_manifest ORDER BY upload_date DESC"
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["associated_case_ids"] = json.loads(d.pop("associated_case_ids_json", "[]"))
        result.append(d)
    return result


def export_source_manifest_csv() -> str:
    """Exports the immutable source provenance manifest as a downloadable CSV string and file."""
    records = list_provenance_records()
    headers = [
        "dataset_id",
        "original_filename",
        "original_source_url",
        "source_organization",
        "dataset_version",
        "acquisition_date",
        "upload_date",
        "file_format",
        "file_size_bytes",
        "license_information",
        "sha256_checksum",
        "processing_status",
        "normalization_version",
        "associated_case_ids",
        "integrity_status",
        "last_verified_at",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=headers)
    writer.writeheader()
    for rec in records:
        row_copy = {k: rec.get(k, "") for k in headers}
        row_copy["associated_case_ids"] = ";".join(rec.get("associated_case_ids", []))
        writer.writerow(row_copy)
    csv_text = buf.getvalue()
    export_path = settings.export_storage_dir / "source_manifest.csv"
    export_path.write_text(csv_text, encoding="utf-8")
    return csv_text
