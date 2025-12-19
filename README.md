# Metadata Pilot

A metadata management system (os.meta.v2) for truly leveraging organizational knowledge assets.

## Overview

This repository provides a database-centric architecture for managing file metadata. It migrates from the traditional YAML sidecar file approach to centralized management via SQLite database, solving the following challenges:

- Metadata linking independent of file names
- Centralized management of scattered metadata files
- Automatic synchronization of metadata when files are updated
- Fast search and query capabilities

## Architecture

### Core Principles

1. **File name-independent linking**: Reliable linking via file hash values and unique IDs
2. **Centralized management with common format**: All metadata stored in a single `.db` file
3. **Update guarantee**: Metadata automatically synchronizes when files are updated

### System Structure

```
metadata-pilot/
├── .cursor/
│   └── rules/          # Metadata enforcement rules for Cursor IDE
├── os_meta/           # Schema, vocabulary, entity registry, policy
│   ├── schema.yaml    # Metadata schema definition
│   ├── vocab.yaml     # Allowed value vocabulary
│   ├── entity_registry.yaml  # Entity ID registry
│   ├── policy_rules.yaml     # Policy rules
│   └── metadata.db    # Metadata database (SQLite)
└── tools/
    ├── osmeta.py      # Metadata management tool
    ├── osmeta_config.yaml  # Configuration file
    └── hooks/         # Git hooks (pre-commit, pre-push)
```

## Quick Start

### 1. Install Dependencies

```bash
pip install pyyaml
```

### 2. Create Metadata

Create or update metadata for files:

```bash
python3 tools/osmeta.py create "path/to/file.md"
python3 tools/osmeta.py update "path/to/file.md"
python3 tools/osmeta.py check "path/to/file.md"
```

### 3. Search Metadata

Search metadata from the database:

```bash
python3 tools/osmeta.py search --content-origin=source
python3 tools/osmeta.py search --scope=internal
python3 tools/osmeta.py stats
```

## Metadata Schema

Metadata is organized into the following main categories:

- **File Tracking**: Path, hash, size, MIME type
- **Boundary Management**: Scope, tenant, project, department, geography
- **Security**: Classification, PII, export control, retention period
- **Truth**: Status, temporality, basis date, source grade
- **Rights Management**: Reuse, execution permissions
- **Execution Control**: Execution surface, radius, approval requirements
- **Facets**: Domain, work types, intent, entities

See `os_meta/schema.yaml` for details.

## Key Features

### Directory-based Inference

Automatically infers default metadata values based on file placement:

- `docs/01_resource/**` → `content_origin: source` (closed source)
- `docs/02_derived/**` → `content_origin: derived` (reusable)

### Source/Derived Principle

- **SOURCE**: No reuse, no export, no execution (read-only)
- **DERIVED**: Reuse, export, and execution possible based on metadata

### Automatic Validation

Metadata is automatically validated from the following perspectives:

- Schema compliance (`schema.yaml`)
- Vocabulary compliance (`vocab.yaml`)
- Entity ID validity (`entity_registry.yaml`)
- Policy rule application (`policy_rules.yaml`)

## Command Reference

### `create`
Create new metadata for a file

```bash
python3 tools/osmeta.py create "path/to/file.md"
```

### `update`
Update metadata for an existing file

```bash
python3 tools/osmeta.py update "path/to/file.md"
```

### `check`
Validate metadata

```bash
python3 tools/osmeta.py check "path/to/file.md"
```

### `rename`
Update metadata when renaming a file

```bash
python3 tools/osmeta.py rename "old/path.md" "new/path.md"
```

### `search`
Search metadata

```bash
python3 tools/osmeta.py search --content-origin=source --scope=internal
```

### `stats`
Display database statistics

```bash
python3 tools/osmeta.py stats
```

## License

See LICENSE file for license information.

## Contributing

Issues and pull requests are welcome. Please review the rules in `.cursor/rules/` before contributing.
