# Sanitized historical reference: source-specific evidence and live configuration are not distributed.
#!/usr/bin/env python3
'Finish the already-running Raw-header job with read-only verification; never retry writes.'
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time

BASE = Path(__file__).resolve().parent
PYTHON = '/private/migration-example/python'


def save(value):
    value['updated_at'] = datetime.now(timezone.utc).isoformat()
    temporary = BASE / 'completion-status.json.tmp'
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(BASE / 'completion-status.json')


def main():
    os.umask(0o077)
    process = json.loads((BASE / 'run-process.json').read_text())
    pid = int(process['pid'])
    while True:
        result = subprocess.run(
            ['ps', '-p', str(pid), '-o', 'stat=', '-o', 'command='],
            capture_output=True, text=True, check=False,
        )
        parts = result.stdout.strip().split(None, 1)
        alive = (result.returncode == 0 and len(parts) == 2
                 and not parts[0].startswith('Z')
                 and str(BASE / 'raw_header_runner.py') in parts[1])
        checkpoint = json.loads((BASE / 'state/checkpoint.json').read_text())
        counts = dict(Counter(state['status'] for state in checkpoint['states'].values()))
        save({'phase': 'importing' if alive else 'import_process_finished',
              'import_pid': pid, 'counts': counts, 'source_count': 2897})
        if not alive:
            break
        time.sleep(10)
    report_path = BASE / 'state/final-report.json'
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    if report.get('complete') is not True:
        save({'phase': 'needs_review', 'import_pid': pid, 'counts': counts,
              'source_count': 2897, 'gmail_writes_retried': False,
              'detail': 'Import stopped before completion; inspect checkpoint and run.log. No automatic write retry.'})
        return 2
    save({'phase': 'verifying', 'import_pid': pid, 'counts': counts, 'source_count': 2897})
    with (BASE / 'final-verification.log').open('ab', buffering=0) as log:
        verified = subprocess.run([PYTHON, str(BASE / 'verify_final.py')],
                                  stdin=subprocess.DEVNULL, stdout=log,
                                  stderr=subprocess.STDOUT, cwd=BASE, check=False)
    save({'phase': 'verified' if verified.returncode == 0 else 'verification_needs_review',
          'import_pid': pid, 'counts': counts, 'source_count': 2897,
          'verification_return_code': verified.returncode,
          'result': str(BASE / 'RUN_RESULT.md')})
    return verified.returncode


if __name__ == '__main__':
    raise SystemExit("Archived reference variant. Use the configurable v2 engine at the repository root.")
    raise SystemExit(main())
