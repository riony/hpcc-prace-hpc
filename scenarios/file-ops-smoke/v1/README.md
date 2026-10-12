# file-ops-smoke v1

Non-security smoke scenario for tracing, replay, and reporting.

Operations (one tool call each):

1. `file.mkdir` → `/tmp/prace-file-ops-smoke-v1/demo-dir`
2. `file.write` → `test-file-1.txt`
3. `file.write` → `test-file-2.txt`
4. `file.delete` → `test-file-1.txt`

Action events use phase `record` (not `attack`). Security assertions are
intentionally absent.

```bash
python3 -m validation.examples.file_ops_smoke_demo \
  --output-dir /absolute/new/run-directory
```
