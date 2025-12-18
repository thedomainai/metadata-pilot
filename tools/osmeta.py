#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("Missing dependency: pyyaml. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
OS_META_DIR = os.path.join(ROOT, "os_meta")
SCHEMA_PATH = os.path.join(OS_META_DIR, "schema.yaml")
VOCAB_PATH = os.path.join(OS_META_DIR, "vocab.yaml")
REGISTRY_PATH = os.path.join(OS_META_DIR, "entity_registry.yaml")
POLICY_PATH = os.path.join(OS_META_DIR, "policy_rules.yaml")
CONFIG_PATH_DEFAULT = os.path.join(ROOT, "tools", "osmeta_config.yaml")
DB_PATH = os.path.join(OS_META_DIR, "metadata.db")


# ---------------------------
# Utilities
# ---------------------------

def now_iso() -> str:
    # local time with offset not trivial; keep ISO without tz for simplicity.
    return dt.datetime.now().replace(microsecond=0).isoformat()

def generate_id() -> str:
    """Generate a unique ID for metadata (uuid-based)"""
    return f"uuid:{uuid.uuid4()}"

def read_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def write_yaml(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sidecar_path(file_path: str) -> str:
    return file_path + ".meta.yaml"

def is_markdown(path: str) -> bool:
    return path.lower().endswith(".md")

def forbid_frontmatter(md_path: str) -> None:
    """
    Enforce "no frontmatter" rule for markdown.
    Note: this checks strict YAML frontmatter (--- on first line).
    """
    with open(md_path, "r", encoding="utf-8") as f:
        txt = f.read()
    if txt.startswith("---\n") or txt.startswith("---\r\n"):
        raise ValueError(f"Frontmatter detected in markdown (forbidden): {md_path}")

def load_vocab() -> Dict[str, Any]:
    return read_yaml(VOCAB_PATH)

def load_registry() -> Dict[str, Any]:
    return read_yaml(REGISTRY_PATH)

def load_schema() -> Dict[str, Any]:
    return read_yaml(SCHEMA_PATH)

def load_policy() -> Dict[str, Any]:
    return read_yaml(POLICY_PATH)


# ---------------------------
# Database Layer
# ---------------------------

class MetadataDB:
    """
    SQLite database for metadata indexing and fast queries.
    .meta.yaml files remain the source of truth, DB is a cache/index.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._path_cache: Dict[str, Tuple[str, float]] = {}  # {path: (id, mtime)}

    def _init_schema(self) -> None:
        """Initialize database schema"""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id TEXT PRIMARY KEY,
                schema_id TEXT,
                schema_rev INTEGER,

                -- File tracking
                file_sha256 TEXT NOT NULL,
                file_mime TEXT,
                file_size_bytes INTEGER,
                file_path_current TEXT NOT NULL,
                file_path_prev TEXT,  -- JSON array
                created_at TEXT,
                updated_at TEXT,

                -- Content origin
                content_origin TEXT,

                -- Boundary
                boundary_scope TEXT,
                boundary_tenant TEXT,
                boundary_project TEXT,
                boundary_department TEXT,
                boundary_geo TEXT,

                -- Security
                sec_class TEXT,
                sec_pii TEXT,
                sec_export TEXT,
                sec_retention TEXT,

                -- Truth
                truth_status TEXT,
                truth_temporal TEXT,
                truth_basis_date TEXT,
                truth_source_grade TEXT,

                -- Rights
                rights_reuse TEXT,
                rights_exec TEXT,

                -- Execution
                exec_surface TEXT,  -- JSON array
                exec_radius TEXT,
                exec_requires_approval TEXT,

                -- Facets (JSON arrays)
                facet_domains TEXT,
                facet_work_types TEXT,
                facet_intents TEXT,
                facet_entities TEXT,

                -- Text
                text_title TEXT,
                text_summary_redacted_1l TEXT,
                text_summary_internal_1l TEXT,

                -- References
                ref_text_extracted TEXT,
                ref_thumbnail TEXT,
                ref_embedding TEXT,

                -- Computed
                comp_route_targets TEXT,  -- JSON array
                comp_label_quality TEXT,
                comp_conflicts TEXT,  -- JSON array
                comp_safety_mode TEXT,
                comp_last_compiled_at TEXT
            )
        """)

        # Indexes for common queries
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_path ON metadata(file_path_current)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON metadata(file_sha256)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_scope ON metadata(boundary_scope)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_sec_class ON metadata(sec_class)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_content_origin ON metadata(content_origin)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_truth_status ON metadata(truth_status)")
        self.conn.commit()

    def _dict_to_row(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Convert metadata dict to database row (serialize JSON fields)"""
        row = meta.copy()

        # Serialize JSON fields
        json_fields = [
            'file_path_prev', 'exec_surface', 'facet_domains',
            'facet_work_types', 'facet_intents', 'facet_entities',
            'comp_route_targets', 'comp_conflicts'
        ]
        for field in json_fields:
            if field in row and row[field] is not None:
                row[field] = json.dumps(row[field])

        return row

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert database row to metadata dict (parse JSON fields)"""
        meta = dict(row)

        # Parse JSON fields
        json_fields = [
            'file_path_prev', 'exec_surface', 'facet_domains',
            'facet_work_types', 'facet_intents', 'facet_entities',
            'comp_route_targets', 'comp_conflicts'
        ]
        for field in json_fields:
            if field in meta and meta[field]:
                try:
                    meta[field] = json.loads(meta[field])
                except (json.JSONDecodeError, TypeError):
                    meta[field] = []

        return meta

    def upsert(self, meta: Dict[str, Any]) -> None:
        """Insert or update metadata record"""
        row = self._dict_to_row(meta)

        # Get all field names from the metadata
        fields = list(row.keys())
        placeholders = ', '.join(['?' for _ in fields])
        field_names = ', '.join(fields)
        update_clause = ', '.join([f'{f} = excluded.{f}' for f in fields if f != 'id'])

        query = f"""
            INSERT INTO metadata ({field_names})
            VALUES ({placeholders})
            ON CONFLICT(id) DO UPDATE SET {update_clause}
        """

        values = [row[f] for f in fields]
        self.conn.execute(query, values)
        self.conn.commit()

    def get_by_id(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata by ID"""
        row = self.conn.execute(
            "SELECT * FROM metadata WHERE id = ?",
            (file_id,)
        ).fetchone()

        return self._row_to_dict(row) if row else None

    def get_by_path(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get metadata by current file path"""
        abs_path = os.path.abspath(file_path)
        row = self.conn.execute(
            "SELECT * FROM metadata WHERE file_path_current = ?",
            (abs_path,)
        ).fetchone()

        return self._row_to_dict(row) if row else None

    def get_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get metadata by file SHA256 hash"""
        row = self.conn.execute(
            "SELECT * FROM metadata WHERE file_sha256 = ?",
            (file_hash,)
        ).fetchone()

        return self._row_to_dict(row) if row else None

    def get_by_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a file using intelligent search:
        1. Check cache (mtime-based)
        2. Search by path
        3. Search by hash (detects file renames)
        """
        abs_path = os.path.abspath(file_path)

        if not os.path.exists(abs_path):
            return None

        mtime = os.path.getmtime(abs_path)

        # Check cache
        if abs_path in self._path_cache:
            cached_id, cached_mtime = self._path_cache[abs_path]
            if cached_mtime == mtime:
                result = self.get_by_id(cached_id)
                if result:
                    return result

        # Search by path first (fastest)
        result = self.get_by_path(abs_path)
        if result:
            # Verify hash matches (detect content changes)
            current_hash = sha256_file(abs_path)
            if result['file_sha256'] == current_hash:
                self._path_cache[abs_path] = (result['id'], mtime)
                return result
            else:
                # Content changed, update hash
                result['file_sha256'] = current_hash
                result['updated_at'] = now_iso()
                self.upsert(result)
                self._path_cache[abs_path] = (result['id'], mtime)
                return result

        # Search by hash (detects file renames)
        current_hash = sha256_file(abs_path)
        result = self.get_by_hash(current_hash)
        if result:
            # File was renamed, update path
            old_path = result['file_path_current']
            prev_paths = result.get('file_path_prev', []) or []
            if old_path not in prev_paths:
                prev_paths.append(old_path)

            result['file_path_current'] = abs_path
            result['file_path_prev'] = prev_paths
            result['updated_at'] = now_iso()
            self.upsert(result)
            self._path_cache[abs_path] = (result['id'], mtime)
            return result

        return None

    def delete(self, file_id: str) -> None:
        """Delete metadata by ID"""
        self.conn.execute("DELETE FROM metadata WHERE id = ?", (file_id,))
        self.conn.commit()

    def search(self, **filters) -> List[Dict[str, Any]]:
        """Search metadata with filters"""
        conditions = []
        values = []

        for key, value in filters.items():
            if value is not None:
                conditions.append(f"{key} = ?")
                values.append(value)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM metadata WHERE {where_clause}"

        rows = self.conn.execute(query, values).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def count(self) -> int:
        """Count total metadata records"""
        return self.conn.execute("SELECT COUNT(*) FROM metadata").fetchone()[0]

    def close(self) -> None:
        """Close database connection"""
        self.conn.close()


# ---------------------------
# Path inference
# ---------------------------

def normalize_client_id(slug: str, registry: Dict[str, Any]) -> Optional[str]:
    target = f"client:{slug.lower()}"
    for c in registry.get("clients", []) or []:
        if c.get("id") == target:
            return target
    return None

def infer_from_path(rel_path: str, cfg: Dict[str, Any], registry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies first matching rule in cfg.path_inference.
    Supports optional boundary_tenant_template within rule.set.
    """
    inferred: Dict[str, Any] = {}
    rules = cfg.get("path_inference", []) or []
    for rule in rules:
        m = re.match(rule.get("match", ""), rel_path)
        if not m:
            continue
        setv = rule.get("set", {}) or {}
        inferred.update(setv)

        # If rule provides template, normalize against registry if possible.
        tmpl = setv.get("boundary_tenant_template")
        if tmpl:
            slug = m.group(1)
            norm = normalize_client_id(slug, registry)
            if norm:
                inferred["boundary_tenant"] = f"tenant:{norm}"
            else:
                inferred["boundary_tenant"] = "tenant:none"
        break
    return inferred


# ---------------------------
# Schema & validation
# ---------------------------

def allowed_keys_set(schema: Dict[str, Any]) -> set:
    return set(schema.get("allowed_keys", []) or [])

def validate_enums(meta: Dict[str, Any], vocab: Dict[str, Any]) -> List[str]:
    conflicts = []

    scalar_map = {
        "content_origin": "content_origin",  # <--- NEW (source/derived)
        "boundary_scope": "boundary_scope",
        "sec_class": "sec_class",
        "sec_pii": "sec_pii",
        "sec_export": "sec_export",
        "sec_retention": "sec_retention",
        "truth_status": "truth_status",
        "truth_temporal": "truth_temporal",
        "truth_source_grade": "truth_source_grade",
        "rights_reuse": "rights_reuse",
        "rights_exec": "rights_exec",
        "exec_radius": "exec_radius",
        "exec_requires_approval": "exec_requires_approval",
    }
    for k, vocab_key in scalar_map.items():
        v = meta.get(k)
        if v is None:
            continue
        allowed = vocab.get(vocab_key, [])
        if allowed and v not in allowed:
            conflicts.append(f"conflict:unknown_vocab:{k}")

    list_map = {
        "exec_surface": "exec_surface",
        "facet_domains": "facet_domains",
        "facet_work_types": "facet_work_types",
        "facet_intents": "facet_intents",
    }
    for k, vocab_key in list_map.items():
        vals = meta.get(k) or []
        allowed = set(vocab.get(vocab_key, []) or [])
        for item in vals:
            if allowed and item not in allowed:
                conflicts.append(f"conflict:unknown_vocab:{k}")
                break

    return conflicts

def validate_entities(meta: Dict[str, Any], registry: Dict[str, Any]) -> List[str]:
    vals = meta.get("facet_entities") or []
    allowed = set()
    for key in ["clients", "projects", "departments", "tools", "people"]:
        for ent in registry.get(key, []) or []:
            if ent.get("id"):
                allowed.add(ent["id"])

    conflicts = []
    for item in vals:
        if item not in allowed:
            conflicts.append("conflict:unknown_entity")
            break
    return conflicts

def apply_policy_conflicts(meta: Dict[str, Any], policy: Dict[str, Any]) -> List[str]:
    out = []
    for rule in policy.get("rules", []) or []:
        code = rule.get("code")
        when = rule.get("when", {})

        def check_cond(cond: Dict[str, Any]) -> bool:
            key = cond.get("key")
            if cond.get("missing"):
                return key not in meta or meta.get(key) in (None, "", [])
            if "eq" in cond:
                return meta.get(key) == cond["eq"]
            return False

        ok = True
        if "all" in when:
            ok = all(check_cond(c) for c in when["all"])
        elif "any" in when:
            ok = any(check_cond(c) for c in when["any"])

        if ok and code:
            out.append(code)
    return out

def compute_safety(meta: Dict[str, Any], conflicts: List[str]) -> Tuple[str, str]:
    if conflicts:
        return ("locked_down", "auto_low")
    return ("normal", meta.get("comp_label_quality") or "auto_high")


# ---------------------------
# Defaults & clamps (core)
# ---------------------------

def ensure_required(meta: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    """
    Apply config defaults only when missing.
    """
    defaults = cfg.get("defaults", {}) or {}
    text_defaults = cfg.get("text_defaults", {}) or {}
    for k, v in defaults.items():
        meta.setdefault(k, v)

    meta.setdefault("text_title", text_defaults.get("text_title_fallback", "Untitled"))
    meta.setdefault("text_summary_redacted_1l", text_defaults.get("text_summary_redacted_1l_fallback", "TBD"))
    meta.setdefault("text_summary_internal_1l", None)

def apply_directory_backed_inference(meta: Dict[str, Any], rel_path: str, cfg: Dict[str, Any], registry: Dict[str, Any]) -> None:
    """
    Re-apply path inference on update.

    Rules:
    - Always override content_origin if inference provides it (directory is the source of truth).
    - For boundary_scope / boundary_tenant: set only if missing (avoid unexpected changes).
    """
    inferred = infer_from_path(rel_path, cfg, registry)

    if "content_origin" in inferred:
        meta["content_origin"] = inferred["content_origin"]

    # Only fill boundaries if missing (you can tighten this later if you want dir-backed boundary too).
    for k in ["boundary_scope", "boundary_tenant"]:
        if k in inferred and meta.get(k) in (None, "", []):
            meta[k] = inferred[k]

    # Optionally fill other safe defaults if missing
    for k in ["sec_class", "sec_pii", "sec_export", "sec_retention", "rights_reuse", "rights_exec", "exec_radius", "exec_requires_approval", "exec_surface"]:
        if k in inferred and meta.get(k) in (None, "", []):
            meta[k] = inferred[k]

def clamp_source_closed(meta: Dict[str, Any]) -> None:
    """
    Non-negotiable clamp:
    SOURCE must stay closed regardless of manual edits.

    This is the main "cannot collapse" guarantee.
    """
    if meta.get("content_origin") != "source":
        return

    meta["rights_reuse"] = "no_reuse"
    meta["rights_exec"] = "read_only"
    meta["sec_export"] = "deny"

    # Keep execution surface minimal and local
    meta["exec_surface"] = ["fs_read"]
    meta["exec_radius"] = "file"
    meta["exec_requires_approval"] = "yes"


# ---------------------------
# Core compile for a single file -> DB
# ---------------------------

def _compile_meta_for_file(file_path: str, cfg_path: str) -> None:
    """
    Compile metadata for a single file and upsert it into metadata.db.

    - No .meta.yaml sidecar is read or written.
    - Validation is performed against schema/vocab/registry/policy.
    - Existing DB records are reused when possible (id/created_at preserved).
    """
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(abs_path)

    # Enforce markdown frontmatter rule
    if is_markdown(abs_path):
        forbid_frontmatter(abs_path)

    rel_path = os.path.relpath(abs_path, ROOT).replace("\\", "/")

    cfg = read_yaml(cfg_path)
    vocab = load_vocab()
    registry = load_registry()
    schema = load_schema()
    policy = load_policy()

    db = MetadataDB()

    # Try to load existing record (by path/hash); preserves id/created_at when found.
    existing = db.get_by_file(abs_path)
    now = now_iso()

    if existing:
        meta = existing
        meta["updated_at"] = now
    else:
        meta = {}
        meta["schema_id"] = schema.get("schema_id", "os.meta.v2")
        meta["schema_rev"] = schema.get("schema_rev", 1)
        meta["id"] = generate_id()
        meta["created_at"] = now
        meta["updated_at"] = now

    # File tracking
    meta["file_sha256"] = sha256_file(abs_path)
    meta["file_mime"] = "application/octet-stream"
    meta["file_size_bytes"] = os.path.getsize(abs_path)
    meta["file_path_current"] = rel_path

    # Directory-backed inference and defaults
    apply_directory_backed_inference(meta, rel_path, cfg, registry)
    ensure_required(meta, cfg)

    # Hard clamp: SOURCE stays closed
    clamp_source_closed(meta)

    # Conflicts & safety
    conflicts: List[str] = []
    conflicts += validate_enums(meta, vocab)
    conflicts += validate_entities(meta, registry)
    conflicts += apply_policy_conflicts(meta, policy)

    safety_mode, label_quality = compute_safety(meta, conflicts)
    meta["comp_conflicts"] = sorted(set(conflicts))
    meta["comp_safety_mode"] = safety_mode
    meta["comp_label_quality"] = label_quality
    meta["comp_route_targets"] = meta.get("comp_route_targets") or []
    meta["comp_last_compiled_at"] = now_iso()

    # strict keys
    allowed = allowed_keys_set(schema)
    extra = set(meta.keys()) - allowed
    if extra:
        raise ValueError(f"Meta contains extra keys not allowed by schema: {sorted(extra)}")

    # Persist to DB as the single source of truth
    db.upsert(meta)
    db.close()


# ---------------------------
# Commands
# ---------------------------

def create_meta(file_path: str, cfg_path: str) -> None:
    # Backwards-compatible entrypoint:
    # now just compiles metadata for the file into metadata.db.
    _compile_meta_for_file(file_path, cfg_path)

def update_meta(file_path: str, cfg_path: str) -> None:
    # Backwards-compatible entrypoint:
    # now just compiles metadata for the file into metadata.db.
    _compile_meta_for_file(file_path, cfg_path)

def check_meta(file_path: str, cfg_path: str) -> None:
    # Compile & validate into DB; if anything is inconsistent, it will raise.
    _compile_meta_for_file(file_path, cfg_path)

def rename_meta(old_path: str, new_path: str, cfg_path: str) -> None:
    """
    Backwards-compatible shim for old sidecar-based rename.

    With DB as source of truth, file rename is detected by hash/path when
    _compile_meta_for_file is called on the new path; we no longer need to
    move sidecar files.
    """
    # We ignore old_path on purpose; DB lookup is hash-based when needed.
    _compile_meta_for_file(new_path, cfg_path)

def sync_to_db(target_dir: Optional[str] = None) -> None:
    """
    Legacy command kept for compatibility.

    With DB as the primary store, there is nothing to sync from .meta.yaml.
    We simply report basic DB stats so existing scripts don't break.
    """
    print("[osmeta] sync command is deprecated; DB is already the source of truth.")
    stats_db()

def search_db(**filters) -> None:
    """Search metadata database"""
    db = MetadataDB()
    results = db.search(**filters)
    db.close()

    if not results:
        print("[osmeta] No results found")
        return

    print(f"[osmeta] Found {len(results)} results:")
    for result in results:
        print(f"  - {result['id']}: {result['file_path_current']}")
        print(f"    origin={result.get('content_origin')}, scope={result.get('boundary_scope')}, sec={result.get('sec_class')}")

def stats_db() -> None:
    """Show database statistics"""
    db = MetadataDB()

    total = db.count()
    print(f"[osmeta] Database statistics:")
    print(f"  Total records: {total}")

    # Count by content_origin
    origins = db.search()
    origin_counts = {}
    for r in origins:
        origin = r.get('content_origin', 'unknown')
        origin_counts[origin] = origin_counts.get(origin, 0) + 1

    print(f"\n  By content_origin:")
    for origin, count in sorted(origin_counts.items()):
        print(f"    {origin}: {count}")

    # Count by boundary_scope
    scope_counts = {}
    for r in origins:
        scope = r.get('boundary_scope', 'unknown')
        scope_counts[scope] = scope_counts.get(scope, 0) + 1

    print(f"\n  By boundary_scope:")
    for scope, count in sorted(scope_counts.items()):
        print(f"    {scope}: {count}")

    # Count by sec_class
    sec_counts = {}
    for r in origins:
        sec = r.get('sec_class', 'unknown')
        sec_counts[sec] = sec_counts.get(sec, 0) + 1

    print(f"\n  By sec_class:")
    for sec, count in sorted(sec_counts.items()):
        print(f"    {sec}: {count}")

    db.close()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=CONFIG_PATH_DEFAULT)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create")
    p_create.add_argument("path")

    p_update = sub.add_parser("update")
    p_update.add_argument("path")

    p_check = sub.add_parser("check")
    p_check.add_argument("path")

    p_rename = sub.add_parser("rename")
    p_rename.add_argument("old_path")
    p_rename.add_argument("new_path")

    p_sync = sub.add_parser("sync", help="Sync all .meta.yaml files to database")
    p_sync.add_argument("--dir", default=None, help="Directory to scan (default: repository root)")

    p_search = sub.add_parser("search", help="Search metadata database")
    p_search.add_argument("--content-origin", dest="content_origin", help="Filter by content_origin")
    p_search.add_argument("--scope", dest="boundary_scope", help="Filter by boundary_scope")
    p_search.add_argument("--sec-class", dest="sec_class", help="Filter by sec_class")

    p_stats = sub.add_parser("stats", help="Show database statistics")

    args = ap.parse_args()

    try:
        if args.cmd == "create":
            create_meta(args.path, args.config)
        elif args.cmd == "update":
            update_meta(args.path, args.config)
        elif args.cmd == "check":
            check_meta(args.path, args.config)
        elif args.cmd == "rename":
            rename_meta(args.old_path, args.new_path, args.config)
        elif args.cmd == "sync":
            sync_to_db(args.dir)
        elif args.cmd == "search":
            filters = {}
            if args.content_origin:
                filters['content_origin'] = args.content_origin
            if args.boundary_scope:
                filters['boundary_scope'] = args.boundary_scope
            if args.sec_class:
                filters['sec_class'] = args.sec_class
            search_db(**filters)
        elif args.cmd == "stats":
            stats_db()
        else:
            raise ValueError("Unknown command")
    except Exception as e:
        print(f"[osmeta] ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print("[osmeta] OK")

if __name__ == "__main__":
    main()