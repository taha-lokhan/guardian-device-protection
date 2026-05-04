# Security Policy

## Supported Versions

| Version | Supported |
|---------|----------|
| 2.x     | Yes      |
| 1.x     | No       |

## Reporting a Vulnerability

Guardian Device Protection handles sensitive operations (remote wipe, lock, GPS tracking). Security issues are taken seriously.

**Please do NOT report security vulnerabilities via public GitHub Issues.**

Instead, report vulnerabilities privately:

- **GitHub Private Reporting**: Use [Security Advisories](../../security/advisories/new) on this repo
- **Email**: Contact the repo owner via GitHub profile

### What to Include

When reporting, please include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

- Acknowledgement within **48 hours**
- Status update within **7 days**
- Fix or mitigation plan within **30 days** for critical issues

## Security Design Notes

This project is a **self-hosted, private anti-theft system**. Key security properties:

- All API endpoints (except `/health`) require **TOTP + master password** authentication
- The nuke (remote wipe) system requires **3-step confirmation**: passphrase + "NUKE" text + TOTP
- No credentials are stored in this repository — all secrets are loaded via environment variables
- WireGuard is used for private network transport between devices and the relay server
- The `DASHBOARD_ORIGIN` environment variable must be set to your dashboard URL to enforce CORS

## Credential Rotation

If you believe any deployed credentials (MQTT password, TOTP secret, master password, nuke passphrase) have been compromised:

1. Immediately update all values in your `.env` file on the VPS
2. Restart the relay server
3. Re-run `install_mac.sh` / reconfigure the Windows and Android agents with new credentials
4. Rotate your WireGuard keys if the VPS was accessed
