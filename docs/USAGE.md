# Running the tools

Requires Python 3.11+ on macOS or Linux. Windows is not supported directly because the implementation uses `fcntl` locks and Unix file permissions.

## Offline inspection

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python gmail_eml_migration_v2.py --help
.venv/bin/python pilot/gmail_eml_pilot.py --help
```

Tests create fictional messages in temporary directories. No live Google access is needed.

## Prepare your own migration

Copy [profile.example.json](../examples/profile.example.json) into an owner-only runtime directory and replace every example path and address. Keep the source directory separate from state and credentials.

Supply your own OAuth Desktop application JSON. The engine validates its type and approved Google OAuth endpoints; profile loading binds its client ID and SHA-256. Do not put credentials in the repository.

```sh
.venv/bin/python gmail_eml_migration_v2.py prepare --profile /absolute/runtime/profile.json
.venv/bin/python gmail_eml_migration_v2.py status --profile /absolute/runtime/profile.json
```

`prepare` inventories source messages and creates local state. It does not import messages or authorize Google access. Review its source count, folder policy, duplicate decisions and repairs.

## Explicit authorization and import

`authorize` is the interactive phase. It verifies the exact Google destination and persists an offline grant. The engine requests Gmail insert, read-only and label scopes; this is mailbox-scoped OAuth, not domain-wide delegation.

```sh
.venv/bin/python gmail_eml_migration_v2.py authorize --profile /absolute/runtime/profile.json
.venv/bin/python gmail_eml_migration_v2.py run \
  --profile /absolute/runtime/profile.json \
  --confirm-destination person@example.org \
  --confirm-source-count 5
```

Replace the destination and count with the exact reviewed values. The `run` command writes to Gmail. Do not run two importers against the same destination or state.

The example uses macOS Keychain under a publication-specific service name. Linux users can configure the engine's file token store in a dedicated owner-only directory; the implementation validates regular-file, ownership, symlink and permission constraints.

On a blocked run, inspect state and use the explicit `review --help` workflow. A lost response must be reconciled before another import; a provider security rejection must not be bypassed by an automatic transformation.

## Pilot variant

The pilot takes a frozen manifest containing exactly five messages, expected source counts/bytes, message identities and hashes, OAuth client identity and checkpoint location. Without `--execute`, it performs offline preflight only.

```sh
.venv/bin/python pilot/gmail_eml_pilot.py \
  --manifest /absolute/runtime/pilot-manifest.json \
  --credentials /absolute/runtime/oauth-client.json \
  --checkpoint /absolute/runtime/pilot-checkpoint.json
```

The publication makes the source and destination configurable through the frozen manifest while retaining exact account verification and explicit execution confirmation. [The pilot tests](../tests/test_pilot.py) show the manifest structure using fictional data.

## Interpret the result

Review source denominator, verified Gmail coverage, duplicates, local-only exceptions and unresolved states separately. Receipt metadata verification and targeted MIME checks do not establish universal byte equivalence or coverage of folders outside the frozen export.
