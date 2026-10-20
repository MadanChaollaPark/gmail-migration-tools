# Gmail migration tools

**Python tooling for source-preserving EML imports, resumable uploads and independent Gmail verification.**

Developed during Cafe24 → Google Workspace migration work for ITCCK. This repository presents the software engineering: immutable source inventories, OAuth account binding, atomic checkpoints, duplicate handling, MIME repairs and recovery from ambiguous network outcomes.

[![Offline tests](https://github.com/MadanChaollaPark/gmail-migration-tools/actions/workflows/test.yml/badge.svg)](https://github.com/MadanChaollaPark/gmail-migration-tools/actions/workflows/test.yml)

[Engineering case study](docs/CASE_STUDY.md) · [All variants](docs/VARIANTS.md) · [Run locally](docs/USAGE.md) · [Publication scope](docs/PUBLICATION.md)

## Engineering highlights

| Problem | Implementation |
| --- | --- |
| Preserve evidence | SHA-256 inventory of source EMLs; repairs affect upload copies only |
| Resume safely | Atomic checkpoint replacement, filesystem locks and per-message state |
| Avoid wrong-account imports | Exact Gmail destination verification and credential/profile binding |
| Handle lost responses | Mark uncertain uploads and reconcile before another write |
| Prevent silent duplicates | Message-ID checks, prepared-byte fingerprints and explicit collision policies |
| Verify outcomes | Gmail receipt readback and final reconciliation |
| Handle rejected mail | Preserve local originals and distinguish source accounting from Gmail coverage |

## Implementations

| Implementation | Status | Purpose |
| --- | --- | --- |
| [v2 engine](gmail_eml_migration_v2.py) | Runnable; recommended starting point | Configurable prepare, authorize, run, status and review phases |
| [Five-message pilot](pilot/gmail_eml_pilot.py) | Runnable; explicit execution required | Bounded import with frozen-manifest and destination checks |
| [Batch v1](archive/batch_v1/) | Sanitized reference | Earlier batch gates, reconciliation and exception handling |
| [Raw-header adapter](archive/raw_header/) | Sanitized reference | MIME-tree comparison and header-normalization fallback |
| [RFC822 adapter](archive/rfc822/) | Sanitized reference | Fingerprint-bound attached-message repair, duplicate equivalence and destination locking |
| [Earlier revisions](archive/revisions/) | Sanitized reference | Four preserved revisions showing the evolution of recovery and verification |

The archive includes the associated preparation scripts, supervisors, verifiers and historical tests. Its original mailbox evidence is not distributed, and archived command entrypoints are disabled. Use the [variant guide](docs/VARIANTS.md) to understand those boundaries.

## Try the offline suite

Python 3.11+ on macOS or Linux (`fcntl` is required).

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python gmail_eml_migration_v2.py --help
```

The supported tests use fictional messages and mocked services. They do not authorize Google access, contact Gmail or import messages.

For an actual migration, follow [the explicit phase-based workflow](docs/USAGE.md) with your own source export and OAuth application.

## Source accounting is not delivery

`accounted_complete` means every source row has a terminal outcome. `gmail_complete` means the required Gmail coverage and labels are satisfied. A preserved local-only rejection can make the first true while the second remains false.

This is historical import tooling, not live mail synchronization. The repository contains no client mail, attachments, credentials, operational manifests or private commit history.
