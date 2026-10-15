# Security reporting

For a suspected issue, contact the repository owner privately through a channel you already trust. Do not post node tokens, subscription URLs, database backups, private keys or passwords in public issues. The project has no dedicated private security-reporting service yet.

Version 0.2 is still an early implementation without an independent security audit. Use HTTPS, trusted nodes, restrictive host access and protected backups. Read `docs/ARCHITECTURE.md` for the implemented trust boundaries and accounting limitations. Do not expose Xray's local statistics or handler API to the network. Protect the node usage journal, state files, migration backups and customer portal URLs as private data.

If an admin account is compromised, reset it using the local CLI to revoke its sessions. Rotate affected node tokens and user credentials, update node environment files and restart agents. Replacing a subscription link alone does not invalidate already downloaded connection credentials.
