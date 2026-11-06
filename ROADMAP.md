# Sealed-core development roadmap

**Current target:** file restore integrity candidate, untagged. Prefer correctness and vault recovery over feature expansion.

1. **File restore staging (integrated candidate, complete):** PR #2 merged, exact main `385c4cd0`, 12/12 unit tests and all nine self-tests passed in CI. Verified missing/corrupt chunks preserve existing file contents; no stable tag was created.
2. **Directory restore rollback (priority):** current `restore_directory(overwrite=True)` removes the old directory before verifying the encrypted archive and extraction. Stage and validate the complete archive first; keep original recoverable on failure, including extraction errors. Acceptance: tampered, missing and invalid tar fixtures cannot destroy existing directory; extracted content matches the sealed source; no unsafe traversal is introduced.
3. **Gatekeeper consistency review:** test duplicate, concurrent and interrupted HMAC/idempotent operations and ticket scope records; document any real defect before modifying policy. Acceptance: no unauthorized cross-scope access, no duplicate intended writes in validated execution paths.
4. **Target-device validation:** run synthetic smoke and recovery tests on trusted Pythonista/iPhone and applicable filesystems before claiming compatibility or stability.

Work in traceable topic branches. Record known limitations and checks with every merge. Preserve local-only operation, repository visibility, secrets, historical snapshots and recovery options.
