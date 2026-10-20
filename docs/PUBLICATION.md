# Publication scope

Prepared on 20 October 2026 from the migration source files available locally.

This is a fresh public repository, with no imported private Git history. Source files were selected explicitly; whole runtime directories were not copied.

## Changes for publication

- Relocated the v2 regression suite to load the repository's engine; isolated the mocked Keychain test from macOS executable availability so it also runs on Linux.
- Replaced client-derived header examples in tests with fictional equivalents.
- Changed the default Keychain service to a separate example namespace.
- Made the pilot's source and destination come from its frozen manifest, preserving explicit confirmation and account verification.
- Anonymized archived addresses, source paths, client IDs, fingerprints and private header examples.
- Disabled archived command entrypoints. The historical data-dependent variants are reference code.
- Added documentation, portable pilot tests and CI.

No original messages, attachments, tokens, OAuth client files, checkpoint data, manifests, customer reports, mail subjects, mailbox IDs or raw production logs are distributed. The published variant manifest describes source code files only.

## Validation boundaries

CI runs the portable tests and syntax checks. It does not authorize Google, retrieve mail, import messages or read Keychain credentials. Archived fixture-dependent tests are outside that portable suite.

The current publication preserves code from the discovered local variants; it does not claim to recover every intermediate version that may once have existed on other machines.

The engineering case study describes the actual migration problem. It does not describe planned CRM, website migration or AI work as delivered.
