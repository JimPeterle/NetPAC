# Security Policy

## Supported Versions

Only the latest version on the `main` branch receives security fixes.
Update with `update_netpac.sh` before reporting an issue.

## Reporting a Vulnerability

**Please do not report security vulnerabilities in public issues.**

Report them privately via GitHub instead:
**Security** tab → **Report a vulnerability**.

Please include:

- the NetPAC version (shown in the web interface) or commit
- the affected page, route or file
- steps to reproduce and the impact you observed
- whether a login is required, and with which rights (any user / `admin`)

Reports are handled on a best-effort basis. Once a fix is available, the
advisory is published.

Before reporting, please check the security model below. Behaviour that is
listed there as intended is not considered a vulnerability. Automated or
AI-generated reports that were not verified against a running instance
will be closed.

## Security Model

NetPAC is an automation tool for network administrators. Its design assumes:

- **Internal networks only.** NetPAC must not be reachable from the internet.
  It is meant to run inside a trusted management network.
- **All users are trusted administrators.** Every user can run scripts and
  playbooks, install Python packages and Ansible collections, use all stored
  secrets and change the Git and notification settings. There is no
  separation of rights between users.
- **The local `admin` account** is the only account that can manage users,
  the RADIUS configuration, backups and restores, and the TLS certificate.
- **Scripts and playbooks run on the NetPAC server** as the NetPAC system user.
  Anyone who can run them can read the secrets passed to them and everything
  that user can access.

### Out of scope

The following follow from the model above and are not vulnerabilities:

- a logged-in user running arbitrary code through scripts, playbooks,
  Python packages or Ansible collections
- a logged-in user reading secrets through a script or playbook
- a logged-in user pointing the Git repository or notification channels to
  another server (including requests to internal addresses)
- notifications sent without TLS when configured that way
- issues that require NetPAC to be exposed to the internet

## Built-in Protections

- Login with local password or RADIUS, always followed by TOTP; each TOTP code
  can only be used once
- Login rate limiting (nginx and application)
- Passwords hashed with bcrypt; secrets, tokens and TOTP secrets encrypted
  with Fernet (`ENCRYPTION_KEY`)
- Sessions are invalidated when a user's password or TOTP secret changes
- CSRF protection on all forms, secure session cookies, security headers and
  a Content Security Policy
- RADIUS replies must carry a Message-Authenticator if the installed pyrad
  version supports it (BlastRADIUS, CVE-2024-3596)
- Scripts and playbooks do not inherit NetPAC's own keys or database credentials
- Backups and temporary files are only readable by the NetPAC system user

## Hardening Recommendations

- Restrict access to port 443 to your management network with a firewall.
- Change the default `admin` password immediately after installation.
- Keep a secure copy of `secret.env`. Without the `ENCRYPTION_KEY`, stored
  secrets and TOTP secrets cannot be decrypted (see README,
  "Lost or changed ENCRYPTION_KEY").
- Keep the server up to date (e.g. `unattended-upgrades`); NetPAC's Python
  dependencies are installed from the system packages.
- Replace the self-signed certificate with one from your internal CA.
- Only add users who are allowed to administer the managed devices.
