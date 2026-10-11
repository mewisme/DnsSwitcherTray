# DNS Switcher Tray

A lightweight Windows system tray app for switching DNS profiles, written in Rust.

## Features

- 16 built-in DNS profiles, including Cloudflare, Google, Quad9, AdGuard, OpenDNS, Control D, and CleanBrowsing.
- Select a network adapter and switch DNS directly from the tray menu.
- Detect the active profile, verify changes, and restore automatic DNS (DHCP).
- Optional elevated autostart without repeated UAC prompts after initial setup.
- No custom profiles, configuration editor, or extra runtime.

## Install

Download **DnsSwitcherTray.exe** from [Releases](https://github.com/mewisme/DnsSwitcherTray/releases) (Windows x64) and run it. Approve the initial Windows administrator prompt to allow DNS changes.

Choose a network adapter in the tray menu, then select a DNS profile. To start with Windows, choose **Enable elevated autostart** in the same menu. Initial setup requires administrator approval.

## Autostart

On the first launch, approve Windows UAC. In the tray menu, select **Enable elevated autostart**. The app copies its executable to a protected folder in Program Files and registers a highest-privilege Scheduled Task for your Windows logon.

At subsequent logons, Windows launches the authorized task without another UAC prompt. Opening the app manually also delegates to that task when one is installed. **Disable elevated autostart** removes the task without changing DNS settings.

## Build

Requires Windows and the Rust MSVC toolchain.

```powershell
cargo build --release --locked
```

The executable is at `target/release/DnsSwitcherTray.exe`. Run tests with `cargo test --locked`.

## Reporting

Report non-security bugs using the [bug report form](https://github.com/mewisme/DnsSwitcherTray/issues/new/choose). For vulnerabilities, follow the [security policy](SECURITY.md) and disclose privately.

## License

[MIT](LICENSE) © 2026 Mew.
