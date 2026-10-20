# Upload-script variants

This publication preserves the three upload engines, two mailbox-adapter families and four distinct intermediate revisions found in the local migration workspaces. Associated preparation, supervision, verification and regression scripts are included.

| Path | What to inspect | Execution status |
| --- | --- | --- |
| `gmail_eml_migration_v2.py` | Configurable profiles, offline OAuth persistence, atomic checkpoints, retry classification and reconciliation | Supported CLI; portable offline tests |
| `pilot/gmail_eml_pilot.py` | Exact five-message pilot; offline preflight by default; explicit execution and destination confirmation | Supported CLI; portable offline tests |
| `archive/batch_v1/gmail_eml_full_import.py` | Bounded uploads, reviewed exception sets, uncertain-outcome recovery and batch verification gates | Reference only |
| `archive/batch_v1/legacy_common.py` | Deterministic preparation, parser checks and source inventory | Reference only |
| `archive/batch_v1/prepare_legacy_full_import.py` | Manifest construction and pilot-to-batch transition | Reference only |
| `archive/batch_v1/gmail_reconcile_source_1632_readonly.py` | Targeted uncertain-upload readback | Reference only |
| `archive/raw_header/raw_header_runner.py` | Comparison of raw headers and decoded MIME-tree content; uncertain-state evidence handling | Reference only |
| `archive/rfc822/runner.py` | Destination lock and adapter-level account guards | Reference only |
| `archive/rfc822/preparation_repairs.py` | Fingerprint-bound RFC822 representation repair and duplicate delivery comparison | Reference only |
| `archive/*/verify_pilot.py` | Pilot content verification | Reference only |
| `archive/*/verify_final.py` | Source, checkpoint, baseline and destination reconciliation | Reference only |
| `archive/*/finish_when_done.py` | Completion supervision without treating process exit as proof of delivery | Reference only |
| `archive/revisions/` | Earlier raw-header, sender-comparison and uncertain-timeout revisions | Reference only |

## Reading the archive

The archived scripts originally depended on reviewed mailbox-specific constants and evidence files. Public copies replace addresses, paths, OAuth client identifiers, source/message fingerprints and private header examples. Their original counts and code structure provide historical context, not configuration for a new mailbox.

Archived `__main__` entrypoints stop with a reference-only message. Tests under `archive/` are historical examples and may require omitted private fixtures; run only the supported `tests/` suite.

The source inventory is recorded in [variant-manifest.json](variant-manifest.json). Runtime files, actual mail, OAuth credentials, logs and operational evidence were never copied into this repository.

For new work, start with v2. Do not reuse a historical exception set or repair policy against a different archive.
