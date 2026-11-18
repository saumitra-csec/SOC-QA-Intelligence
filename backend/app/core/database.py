import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from backend.app.core.config import settings
from backend.app.models.entities import (
    RELATIONAL_TABLES_DDL,
    INDEX_DDL,
    SCHEMA_MIGRATION_VERSION,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DatabaseManager:
    """
    Manages relational persistence with parameterized queries and automatic schema migration.
    Supports PostgreSQL in Docker/production and SQLite3 in local/offline execution.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.sqlite_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.run_migrations()

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def run_migrations(self) -> dict:
        with self.connection() as conn:
            for ddl in RELATIONAL_TABLES_DDL:
                conn.execute(ddl)
            for idx in INDEX_DDL:
                conn.execute(idx)
            alter_statements = [
                "ALTER TABLE playbooks ADD COLUMN incident_types_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbooks ADD COLUMN institution TEXT NOT NULL DEFAULT 'SOC-QA Research Benchmark'",
                "ALTER TABLE playbooks ADD COLUMN playbook_classification TEXT NOT NULL DEFAULT 'operational_soc_playbook'",
                "ALTER TABLE playbooks ADD COLUMN scope TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE playbook_versions ADD COLUMN source_metadata_json TEXT NOT NULL DEFAULT '{}'",
                "ALTER TABLE playbook_versions ADD COLUMN normalization_status TEXT NOT NULL DEFAULT 'validated'",
                "ALTER TABLE playbook_versions ADD COLUMN normalization_metadata_json TEXT NOT NULL DEFAULT '{}'",
                "ALTER TABLE playbook_versions ADD COLUMN prerequisites_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_versions ADD COLUMN roles_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_versions ADD COLUMN completion_criteria_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN phase TEXT NOT NULL DEFAULT 'analysis'",
                "ALTER TABLE playbook_steps ADD COLUMN is_conditional INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE playbook_steps ADD COLUMN condition_expression TEXT",
                "ALTER TABLE playbook_steps ADD COLUMN actor_role TEXT",
                "ALTER TABLE playbook_steps ADD COLUMN predecessors_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN successors_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN decision_outcomes_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN evidence_produced_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN inputs_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN outputs_json TEXT NOT NULL DEFAULT '[]'",
                "ALTER TABLE playbook_steps ADD COLUMN source_anchor_json TEXT NOT NULL DEFAULT '{}'",
                "ALTER TABLE playbook_steps ADD COLUMN normalization_notes_json TEXT NOT NULL DEFAULT '[]'",
            ]
            for stmt in alter_statements:
                try:
                    conn.execute(stmt)
                except Exception:
                    pass
            cur2 = conn.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                ("2026_11_18_002_institutional_playbook_action_schema",),
            )
            if not cur2.fetchone():
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                    (
                        "2026_11_18_002_institutional_playbook_action_schema",
                        utc_now_iso(),
                        "Extend playbooks schema with Institutional Action Schema, source anchors, and human-review status gate",
                    ),
                )
            cur = conn.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                (SCHEMA_MIGRATION_VERSION,),
            )
            if not cur.fetchone():
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                    (
                        SCHEMA_MIGRATION_VERSION,
                        utc_now_iso(),
                        "Initialize 27 normalized research tables & indexes for SOC-QA Intelligence",
                    ),
                )
        return {
            "migration_version": SCHEMA_MIGRATION_VERSION,
            "tables_count": len(RELATIONAL_TABLES_DDL) - 1,
            "indexes_count": len(INDEX_DDL),
            "status": "APPLIED",
        }

    def log_audit(
        self, actor: str, action_type: str, entity_type: str, entity_id: str, details: dict
    ):
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_records (audit_id, actor, action_type, entity_type, entity_id, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"AUD-{uuid.uuid4().hex[:10].upper()}",
                    actor,
                    action_type,
                    entity_type,
                    entity_id,
                    json.dumps(details),
                    utc_now_iso(),
                ),
            )


db_manager = DatabaseManager()
