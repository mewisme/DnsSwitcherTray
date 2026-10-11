# Security Policy

## Supported versions

Security fixes are provided for the latest published release of DNS Switcher Tray only. Older releases, development builds, and forks are not supported. Update to the newest release before reporting a vulnerability.

## Privileged operation

DNS Switcher Tray changes Windows network adapter DNS settings and therefore requires administrator privileges. Its optional elevated autostart registers a privileged startup mechanism after initial UAC approval. Treat both elevation and autostart as security-sensitive: download binaries only from the official [GitHub Releases](https://github.com/mewisme/DnsSwitcherTray/releases), review elevation prompts, and disable elevated autostart when no longer needed. Do not run modified or untrusted builds with administrator rights.

## Report a vulnerability privately

**Do not open a public GitHub issue for a security vulnerability.** Use the repository's [private vulnerability reporting / security advisory form](https://github.com/mewisme/DnsSwitcherTray/security/advisories/new) to contact the maintainers.

Include the affected release, Windows version, impact, reproduction steps, and a minimal proof of concept when safe. Redact credentials, tokens, personal information, IP addresses, and other sensitive network details from evidence. Please allow maintainers time to investigate before public disclosure. If private reporting is unavailable, do not publish exploit details in an issue; contact the repository maintainers through a private channel instead.

For non-security defects, use the [bug report form](https://github.com/mewisme/DnsSwitcherTray/issues/new/choose).
