# Sealed-core development roadmap

**Current target:** directory-restore integrity candidate on a reviewable branch, untagged. Prioritise correctness and vault recovery over feature expansion.

1. **File restore staging (integrated candidate, complete):** PR #2 merged, exact main `385c4cd0`, 12/12 unit tests and all nine self-tests passed in CI. Verified missing/corrupt chunks preserve existing file contents; no stable tag was created.
2. **Directory restore rollback (candidate; PR validation pending):** authenticate the entire archived object and extract into a safe, temporary sibling before any existing destination is moved. Keep old data recoverable through the publication step and on rollback failure. Nine new synthetic tests cover corruption, invalid tar, path traversal, publish failure, rollback failure and normal restoration. Acceptance: all checks and existing tests pass on exact PR revision, no known unmitigated routine corruption-driven data loss; document crash gap and target-device limitations. Do not claim a stable release without platform evidence.
3. **Gatekeeper consistency review:** test duplicate, concurrent and interrupted HMAC/idempotent operations and ticket scope records; document any real defect before modifying policy. Acceptance: no unauthorized cross-scope access, no duplicate intended writes in validated execution paths.
4. **Target-device validation:** run synthetic smoke and recovery tests on trusted Pythonista/iPhone and applicable filesystems before claiming compatibility or stability.

Work in traceable topic branches. Record known limitations and checks with every merge. Preserve local-only operation, repository visibility, secrets, historical snapshots and recovery options.
