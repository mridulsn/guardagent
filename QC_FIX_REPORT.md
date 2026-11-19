# QC fixes, 2026-11-19

Reviewed the interrupted working tree first and retained its correct changes.
Review source: ../_portfolio-shared/qc-guardagent.md. No Claude CLI or model API
was called. Historical model replies, tool payloads and audit entries are intact.

| Finding | Result |
|---|---|
| 1. SQL resource exhaustion | Fixed: per-query Python subprocess, parent deadline, CPU limit, isolated SQLite heap cap, value limit, function allowlist; Linux also gets an address-space limit. Low-limit tests avoid large allocations. |
| 2. Browser freezes | Fixed: disposable worker, parent-controlled cancellation, heap cap, bounded results, resolved table/function restrictions. Offline real-SQLite adapter tests cover infinite recursive aggregation, event-loop responsiveness, cancellation and recovery. Full browser/sql.js smoke verification remains unavailable because the CDN could not be reached. |
| 3. Aggregated exports | Fixed as scoped: row-packing aggregates are denied by both executors and detected independently by the oracle. Documentation now calls this a returned-row budget, not an export boundary. Recursive concatenation remains possible within resource limits; no general export-authorization claim is made. |
| 4. CTE REPLACE | Fixed in both guards: parse the statement following CTEs; preserve legitimate replace() calls. |
| 5. Quoted functions | Fixed in both guards: normalize double-quoted, bracketed and backtick names before checking. |
| 6. Calculator magnitude | Fixed in both evaluators: every node result, including nested function returns, is checked. |
| 7. Numeric parity | Fixed: exact binary-to-decimal half-even rounding, Python floor/remainder semantics, matching leading-zero and decimal-only lexical restrictions. Boundary-generated differential tests pass. |
| 8. Schema/Unicode parity | Fixed: code-point lengths, own-property checks, JSON argument parsing and shared schema fixtures. |
| 9. Outcome classification | Fixed: failed execution is not successful harm; unsuccessful runs without attack attempts are inconclusive. Genuine refusals remain model_declined. |
| 10. Model-result truncation | Fixed: complete ordinary results, structural truncation of oversized results, explicit metadata and exact trace/model payload agreement. Escaped Unicode and oversized metadata are covered. |
| 11. System-object literals | Fixed in both guards: harmless literal values are allowed; single-quoted object references remain protected. |
| 12. Published totals | Fixed: offline refresh script reclassifies recorded traces and regenerates README measurements. Regression checks cover the table and numerical prose. |
| 13. Normal scoring | Fixed: cents, stock/name pairs, tied cities, refund restocking fee and Saturday opening/closing/time-zone relationships. Scoring is explicitly fact presence, not semantic grading of extra claims. |
| 14. Containment boundaries | Fixed/documented: Python table/function authorizer, browser resolved-plan policy, direct-executor regressions and maintained safe HTML rendering checks. Browser limitations are explicit. |

## Verification

- `.venv/bin/python -m pytest -q -p no:cacheprovider`: 356 passed.
- The inherited regression file against an isolated original-HEAD snapshot:
  69 failed, 39 passed; these establish that the regressions catch original bugs.
- Newly added tests were observed failing for browser isolation, schema JSON
  parity, parent deadlines, oversized payload caps, published metrics, refund
  fees, Saturday relationships and aggregate names appearing only in literals,
  before their corresponding remaining fixes.
- ASCII check passed for Python, JavaScript, HTML, CSS and JSON source files.
- `git diff --check` passed.
- `.venv/bin/python -m scripts.refresh_recordings` recomputed classifications
  from web/data/scenarios.json using web/data/shop.db for expected data values.
  No tools or models were replayed. Stored fingerprint-equality observations
  were retained, not fabricated or remeasured.
- The SQL worker test uses native SQLite behind a sql.js-shaped adapter and a
  cancellable subprocess transport. It is not a browser/WASM smoke test.

## Published numbers

- README CLI calls: 109 -> 105 (40 + 37 + 28).
- README test count, in both locations: 235 -> 356.
- README/web inconclusive column: absent -> 0 for each configuration.
- The obsolete approximate 150-line tokenizer description was removed.
- Unchanged after recomputation: normal scores 7/7 and 7/7; guard-blocked attacks
  1, 2, 11; model-declined attacks 11, 10, 1; got-through attacks 0, 0, 0;
  false-positive blocks 0; 17 standard SQL rewrites; 149 of 389 exported rows;
  costs $0.02/$0.95/$1.39; mean latencies 2.8/6.3/11.9 seconds.

## Handoff

Local commit could not be created: `git add` failed with
`Unable to create .../.git/index.lock: Operation not permitted`.
The session grants only read access to .git; approval escalation is unavailable.
All completed changes are in the working tree. Nothing was pushed.

In a session with writable Git metadata, stage the new files and commit with:

```
git add QC_FIX_REPORT.md scripts/refresh_recordings.py src/guardagent/sql_worker.py tests/test_qc_regressions.py tests/test_sql_worker.py web/sql-worker.js
git -c user.name=mridulsn -c user.email=mridul8527@gmail.com commit -am 'Fix QC guard parity, SQL containment, and recorded metrics'
```

Primary vault notes could not be updated because
<local path> is outside the writable roots.
This report retains project results, artifact paths, verification and pending
commit/vault work for later saving.
