# Sealed-core development roadmap

**Current target:** directory-restore integrity candidate merged and tested on main, untagged. Prioritise correctness and vault recovery over feature expansion.

1. **File restore staging (integrated candidate, complete):** PR #2 merged, exact main `385c4cd0`, 12/12 unit tests and all nine self-tests passed in CI. Verified missing/corrupt chunks preserve existing file contents; no stable tag was created.
2. **Directory restore rollback (integrated candidate, complete):** authenticate the entire archived object and extract into a safe, temporary sibling before any existing destination is moved. Keep old data recoverable through the publication step and on rollback failure. Eleven new synthetic cases cover corruption, invalid tar, path traversal, publish failure, rollback failure and normal restoration. [PR #4](https://github.com/levelinglucy/Sealed-core/pull/4) merged at `7e647ed0`; 23/23 unit tests and all 9/9 core self-tests passed in [PR CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42225523051) and [final main CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42225646052), each on Python 3.11/3.12. Crash gap and target-device uncertainties remain; this is not a stable release. Do not claim a stable release without platform evidence.
3. **Gatekeeper consistency review:** test duplicate, concurrent and interrupted HMAC/idempotent operations and ticket scope records; document any real defect before modifying policy. Acceptance: no unauthorized cross-scope access, no duplicate intended writes in validated execution paths.
4. **Target-device validation:** run synthetic smoke and recovery tests on trusted Pythonista/iPhone and applicable filesystems before claiming compatibility or stability.

Work in traceable topic branches. Record known limitations and checks with every merge. Preserve local-only operation, repository visibility, secrets, historical snapshots and recovery options.
