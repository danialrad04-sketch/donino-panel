# Security reporting

For a suspected issue, contact the repository owner privately through a channel you already trust. Do not post node tokens, subscription URLs, database backups, private keys or passwords in public issues. The project has no dedicated private security-reporting service yet.

Version 0.2 is still an early implementation without an independent security audit. Use HTTPS, trusted nodes, restrictive host access and protected backups. Read `docs/ARCHITECTURE.md` for the implemented trust boundaries and accounting limitations. Do not expose Xray's local statistics or handler API to the network. Protect the node usage journal, state files, migration backups and customer portal URLs as private data.

If an admin account is compromised, reset it using the local CLI to revoke its sessions. Rotate affected node tokens and user credentials, update node environment files and restart agents. Replacing a subscription link alone does not invalidate already downloaded connection credentials.

The 1.0 development branch adds TOTP MFA and scoped API tokens. TOTP seeds are encrypted using a private master key (`DONINO_KEY_FILE`); losing this key makes the stored seeds unusable. Preserve the matching key separately when backing up, restoring or migrating the database. Recovery codes are hashed and one-use. Enabling/disabling MFA revokes that account's sessions and API tokens; changing its password/role through the CLI also revokes both. Node tokens and customer subscription/profile credentials remain separate authentication mechanisms and require their own rotation. The foundation is not an independent security audit.
