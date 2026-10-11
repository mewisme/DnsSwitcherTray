#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod dns;
mod privilege;
mod profiles;
mod tray;

fn main() {
    if let Err(error) = app::run() {
        eprintln!("DNS Switcher: {error}");
        #[cfg(windows)]
        tray::fatal_message("DNS Switcher", &error);
    }
}
