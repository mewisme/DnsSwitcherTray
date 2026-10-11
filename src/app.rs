//! Controller for the native tray. No profile editing and no implicit
//! modification of multiple network interfaces.
use crate::dns::{self, Adapter};
use crate::privilege;
use crate::profiles::{BUILTIN_PROFILES, Profile};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug)]
pub enum Action {
    Refresh,
    SelectAdapter(String),
    ApplyProfile(&'static str),
    InstallStartup,
    RemoveStartup,
    Quit,
}

#[derive(Clone)]
pub struct AdapterItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub connected: bool,
    pub selected: bool,
}

pub struct View {
    pub adapters: Vec<AdapterItem>,
    pub selected_name: Option<String>,
    pub profiles: &'static [Profile],
    pub active_profile: Option<&'static str>,
    pub status: String,
    pub busy: bool,
    pub elevated: bool,
    pub autostart: bool,
}

struct State {
    selected: Option<String>,
    adapters: Vec<Adapter>,
    status: String,
}

pub struct App {
    state: Mutex<State>,
    busy: AtomicBool,
}

pub fn run() -> Result<(), String> {
    if !privilege::bootstrap()? {
        return Ok(());
    }
    let app = std::sync::Arc::new(App::new());
    // Keep startup responsive: inventory runs on a worker after the tray icon
    // is visible. The menu shows "Loading" until the first snapshot arrives.
    crate::tray::run(app)
}

impl App {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                selected: load_selected(),
                adapters: vec![],
                status: "Loading network adapters...".to_string(),
            }),
            busy: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> View {
        let state = self.state.lock().expect("app state lock");
        let selected_adapter = state.selected.as_ref().and_then(|id| {
            state
                .adapters
                .iter()
                .find(|adapter| adapter.guid.eq_ignore_ascii_case(id) && is_connected(adapter))
        });
        let active_profile = selected_adapter.and_then(|adapter| {
            BUILTIN_PROFILES
                .iter()
                .find(|profile| matches_profile(adapter, profile))
                .map(|profile| profile.id)
        });
        View {
            adapters: state
                .adapters
                .iter()
                .map(|adapter| AdapterItem {
                    id: adapter.guid.clone(),
                    name: adapter.name.clone(),
                    description: adapter.description.clone(),
                    connected: is_connected(adapter),
                    selected: state
                        .selected
                        .as_ref()
                        .is_some_and(|s| s.eq_ignore_ascii_case(&adapter.guid)),
                })
                .collect(),
            selected_name: selected_adapter.map(|adapter| adapter.name.clone()),
            profiles: BUILTIN_PROFILES,
            active_profile,
            status: state.status.clone(),
            busy: self.busy.load(Ordering::SeqCst),
            elevated: privilege::elevated(),
            autostart: privilege::task_exists(),
        }
    }

    pub fn handle(&self, action: Action) -> Result<String, String> {
        if self.busy.swap(true, Ordering::AcqRel) {
            return Err("Another DNS operation is still running.".to_string());
        }
        let result = match action {
            Action::Refresh => self
                .refresh()
                .map(|_| "Network adapter status updated.".to_string()),
            Action::SelectAdapter(guid) => self.select(&guid),
            Action::ApplyProfile(id) => self.apply(id),
            Action::InstallStartup => privilege::configure_autostart(true),
            Action::RemoveStartup => privilege::configure_autostart(false),
            Action::Quit => Ok("Closing DNS Switcher.".to_string()),
        };
        let mut state = self.state.lock().expect("app state lock");
        state.status = match &result {
            Ok(message) => message.clone(),
            Err(message) => format!("Error: {message}"),
        };
        drop(state);
        self.busy.store(false, Ordering::Release);
        result
    }

    pub fn refresh(&self) -> Result<(), String> {
        let adapters = dns::discover().map_err(|error| error.to_string())?;
        let mut state = self.state.lock().expect("app state lock");
        let saved_connected = state.selected.as_ref().is_some_and(|id| {
            adapters
                .iter()
                .any(|a| a.guid.eq_ignore_ascii_case(id) && is_connected(a))
        });
        if !saved_connected {
            let candidates: Vec<_> = adapters
                .iter()
                .filter(|adapter| is_connected(adapter) && adapter.physical)
                .collect();
            if candidates.len() == 1 {
                state.selected = Some(candidates[0].guid.clone());
            }
        }
        let selected_name = state.selected.as_ref().and_then(|id| {
            adapters
                .iter()
                .find(|a| a.guid.eq_ignore_ascii_case(id) && is_connected(a))
                .map(|a| a.name.as_str())
        });
        state.status = selected_name.map_or_else(
            || "Choose a connected adapter from the tray menu.".to_string(),
            |name| format!("Selected network adapter: {name}"),
        );
        state.adapters = adapters;
        Ok(())
    }

    fn select(&self, id: &str) -> Result<String, String> {
        let mut state = self.state.lock().expect("app state lock");
        let candidate = state
            .adapters
            .iter()
            .find(|adapter| adapter.guid.eq_ignore_ascii_case(id))
            .ok_or_else(|| {
                "Network adapter no longer exists. Refresh the adapter list.".to_string()
            })?;
        if !is_connected(candidate) {
            return Err("Disconnected adapters cannot be selected.".to_string());
        }
        let name = candidate.name.clone();
        let guid = candidate.guid.clone();
        persist_selected(&guid)?;
        state.selected = Some(guid);
        Ok(format!("Selected network adapter: {name}"))
    }

    fn apply(&self, id: &str) -> Result<String, String> {
        if !privilege::elevated() {
            return Err("Administrative rights required. Restart with elevation.".to_string());
        }
        let profile = BUILTIN_PROFILES
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| "DNS profile is not in the fixed built-in catalog.".to_string())?;
        let guid = {
            let state = self.state.lock().expect("app state lock");
            let selected = state
                .selected
                .as_ref()
                .ok_or_else(|| "Choose a network adapter before changing DNS.".to_string())?;
            if !state
                .adapters
                .iter()
                .any(|a| a.guid.eq_ignore_ascii_case(selected) && is_connected(a))
            {
                return Err(
                    "Saved network adapter is disconnected. Choose a connected adapter."
                        .to_string(),
                );
            }
            selected.clone()
        };
        let after = dns::switch(&guid, profile).map_err(|e| e.to_string())?;
        // A successful switch is verified against the OS before reporting.
        self.refresh()?;
        if after.starts_with("Already active") {
            Ok(format!(
                "{} is already active on the selected adapter.",
                profile.name
            ))
        } else {
            Ok(format!("{} applied and verified by Windows.", profile.name))
        }
    }
}

fn is_connected(adapter: &Adapter) -> bool {
    adapter.status.eq_ignore_ascii_case("up")
}

/// An active indicator is shown only when all *available* address families
/// match the fixed preset and report a known matching mode.
fn matches_profile(adapter: &Adapter, profile: &Profile) -> bool {
    let families = [(&adapter.ipv4, profile.ipv4), (&adapter.ipv6, profile.ipv6)];
    let mut count = 0usize;
    for (actual, wanted) in families {
        if !actual.available {
            continue;
        }
        count += 1;
        if profile.automatic {
            if actual.mode != "DHCP" {
                return false;
            }
        } else {
            if actual.mode != "Static"
                || actual.servers.len() != wanted.len()
                || !actual
                    .servers
                    .iter()
                    .zip(wanted)
                    .all(|(a, w)| ip_equal(*a, w))
            {
                return false;
            }
        }
    }
    count > 0
}

fn ip_equal(ip: IpAddr, text: &str) -> bool {
    text.parse::<IpAddr>().is_ok_and(|wanted| ip == wanted)
}

fn settings_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|root| {
        PathBuf::from(root)
            .join("DnsSwitcherTray")
            .join("state.json")
    })
}

fn load_selected() -> Option<String> {
    let path = settings_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    let document: serde_json::Value = serde_json::from_str(&text).ok()?;
    let id = document.get("adapter_guid")?.as_str()?;
    // Only carry a stable adapter identifier between sessions.
    if id.len() == 36 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        Some(id.to_owned())
    } else {
        None
    }
}

fn persist_selected(id: &str) -> Result<(), String> {
    let path = settings_path().ok_or("Cannot locate user AppData settings directory.")?;
    let dir = path.parent().ok_or("Invalid settings path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let json = serde_json::json!({ "adapter_guid": id });
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(&json).unwrap())
        .map_err(|e| e.to_string())?;
    std::fs::rename(&temporary, &path)
        .or_else(|_| {
            // Windows rename doesn't replace an existing file.
            std::fs::remove_file(&path)?;
            std::fs::rename(&temporary, &path)
        })
        .map_err(|e| format!("Could not save preferred adapter: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Family;

    fn adapter() -> Adapter {
        Adapter {
            guid: "00112233-4455-6677-8899-aabbccddeeff".into(),
            index: 10,
            name: "Ethernet".into(),
            description: "Test".into(),
            status: "Up".into(),
            physical: true,
            ipv4: Family {
                available: true,
                servers: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
                mode: "Static".into(),
            },
            ipv6: Family {
                available: false,
                ..Default::default()
            },
        }
    }

    #[test]
    fn active_only_when_dns_mode_and_addresses_match() {
        let p = BUILTIN_PROFILES
            .iter()
            .find(|p| p.id == "cloudflare")
            .unwrap();
        let mut a = adapter();
        assert!(matches_profile(&a, p));
        a.ipv4.mode = "Unknown".into();
        assert!(!matches_profile(&a, p));
    }
    #[test]
    fn no_false_active_when_address_family_available_but_unset() {
        let mut a = adapter();
        a.ipv6.available = true;
        let p = BUILTIN_PROFILES
            .iter()
            .find(|p| p.id == "cloudflare")
            .unwrap();
        assert!(!matches_profile(&a, p));
    }
}
