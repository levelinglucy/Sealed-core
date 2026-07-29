How they work together (zero intrusion surface)
1.  Run the sealed core — everything stays encrypted on disk in sealed_storage/.
2.  Any local script / CLI / cron job calls gatekeeper_request({ "auth_token": ..., "role": ..., "action": ... }) — never directly touches the core.
3.  No network listener — gatekeeper_request is a pure Python function. You can wrap it in a local Unix socket if you ever need IPC, but never expose it over TCP/HTTP.
4.  All secrets are environment-only (export SEALED_OWNER_SECRET=... and SEALED_GATEKEEPER_TOKEN=...).
5.  HELPER roles automatically get redacted data.
6.  Every write is atomic + HMAC-protected — tampering is instantly detectable.
Additional hardening recommendations (beyond code)
•  Run the process as a dedicated low-privilege user with sealed_storage/ owned 700.
•  Use systemd service with ProtectSystem=strict, PrivateTmp=yes, NoNewPrivileges=yes.
•  Never put the passphrase in any script or version control.
•  Periodically run core.watchdog_scan() from a local cron.
•  Back up the sealed_storage/ directory encrypted (e.g. with age or gocryptfs).
These two files now form a complete, auditable, intrusion-resistant sealed ticket system that fully satisfies the original design goals while being usable via the gatekeeper policy layer.
Drop them in, set the two environment variables, and you’re done. No remote calls, no plaintext on disk, no data leakage paths left.
