//! Native Windows DNS discovery and configuration.
//!
//! Windows IP Helper API supplies adapter identities/effective resolver lists;
//! Win32 Registry API reads configured DNS mode; NetIO API changes only DNS
//! servers on an explicit interface GUID. No PowerShell, netsh, shell commands,
//! C# runtime, or per-user custom profile parsing is involved.
use crate::profiles::Profile;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(windows)]
use std::ffi::CStr;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::{null, null_mut};
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
    DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH, SetInterfaceDnsSettings,
};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ, RegCloseKey,
    RegOpenKeyExW, RegQueryValueExW,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
#[cfg(windows)]
use windows_sys::core::GUID;

#[derive(Clone, Debug)]
pub struct Adapter {
    pub guid: String,
    pub index: u32,
    pub name: String,
    pub description: String,
    pub status: String,
    pub physical: bool,
    pub ipv4: Family,
    pub ipv6: Family,
}

#[derive(Clone, Debug, Default)]
pub struct Family {
    pub available: bool,
    pub servers: Vec<IpAddr>,
    /// "Static", "DHCP", or "Unknown". Unknown is never assumed to be automatic.
    pub mode: String,
}

#[derive(Debug)]
pub enum DnsError {
    #[cfg_attr(windows, allow(dead_code))]
    Unsupported,
    Invalid(String),
    Api(String),
    Verification(String),
}
impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "DNS switching requires Windows."),
            Self::Invalid(message) | Self::Api(message) | Self::Verification(message) => {
                write!(f, "{message}")
            }
        }
    }
}
impl std::error::Error for DnsError {}

fn valid_guid(text: &str) -> bool {
    let s = text.trim_matches(|ch| ch == '{' || ch == '}');
    s.len() == 36
        && s.chars().enumerate().all(|(index, ch)| {
            if [8, 13, 18, 23].contains(&index) {
                ch == '-'
            } else {
                ch.is_ascii_hexdigit()
            }
        })
}

#[cfg(windows)]
fn parse_guid(text: &str) -> Result<GUID, DnsError> {
    let raw = text.trim_matches(|ch| ch == '{' || ch == '}');
    if !valid_guid(raw) {
        return Err(DnsError::Invalid("Invalid adapter GUID.".into()));
    }
    let segments: Vec<&str> = raw.split('-').collect();
    let data1 =
        u32::from_str_radix(segments[0], 16).map_err(|e| DnsError::Invalid(e.to_string()))?;
    let data2 =
        u16::from_str_radix(segments[1], 16).map_err(|e| DnsError::Invalid(e.to_string()))?;
    let data3 =
        u16::from_str_radix(segments[2], 16).map_err(|e| DnsError::Invalid(e.to_string()))?;
    let joined = format!("{}{}", segments[3], segments[4]);
    let mut data4 = [0u8; 8];
    for (position, slot) in data4.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&joined[position * 2..position * 2 + 2], 16)
            .map_err(|e| DnsError::Invalid(e.to_string()))?;
    }
    Ok(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn same_addresses(expected: &[IpAddr], actual: &[IpAddr]) -> bool {
    expected == actual
}

fn profile_addresses(input: &[&str], ipv6: bool) -> Result<Vec<IpAddr>, DnsError> {
    if input.len() > 8 {
        return Err(DnsError::Invalid(
            "Too many DNS servers in built-in profile.".into(),
        ));
    }
    let mut unique = Vec::new();
    for raw in input {
        let parsed = raw
            .parse::<IpAddr>()
            .map_err(|_| DnsError::Invalid(format!("Invalid resolver address: {raw}")))?;
        if parsed.is_ipv6() != ipv6
            || parsed.is_unspecified()
            || parsed.is_multicast()
            || unique.contains(&parsed)
        {
            return Err(DnsError::Invalid(
                "Invalid or duplicate DNS address family.".into(),
            ));
        }
        unique.push(parsed);
    }
    Ok(unique)
}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Resolve trusted Microsoft executables under System32, never through PATH.
/// Only the fixed-name Windows autostart helpers call this routine.
#[cfg(windows)]
pub(crate) fn trusted_executable(name: &str) -> Result<PathBuf, DnsError> {
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(DnsError::Invalid("Unexpected Windows utility name.".into()));
    }
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(DnsError::Api(
            "Could not locate the Windows system directory.".into(),
        ));
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])).join(name))
}

#[cfg(windows)]
unsafe fn decode_wide(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    // Bound scanning: malformed OS pointers must never trigger unbounded reads.
    while length < 32_768 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) })
}

#[cfg(windows)]
unsafe fn socket_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let ptr = address.lpSockaddr;
    if ptr.is_null() || address.iSockaddrLength < 2 {
        return None;
    }
    match unsafe { (*ptr).sa_family } {
        AF_INET if (address.iSockaddrLength as usize) >= std::mem::size_of::<SOCKADDR_IN>() => {
            let socket = unsafe { &*(ptr.cast::<SOCKADDR_IN>()) };
            // Network bytes in memory already follow the IPv4 octet order.
            let bytes = unsafe { socket.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        AF_INET6 if (address.iSockaddrLength as usize) >= std::mem::size_of::<SOCKADDR_IN6>() => {
            let socket = unsafe { &*(ptr.cast::<SOCKADDR_IN6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                socket.sin6_addr.u.Byte
            })))
        }
        _ => None,
    }
}

#[cfg(windows)]
fn registry_value(key: HKEY, field: &str) -> Option<String> {
    let name = wide(field);
    let mut kind = 0u32;
    let mut size = 0u32;
    let first =
        unsafe { RegQueryValueExW(key, name.as_ptr(), null(), &mut kind, null_mut(), &mut size) };
    if first != ERROR_SUCCESS
        || size == 0
        || size > 8192
        || ![REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ].contains(&kind)
        || !size.is_multiple_of(2)
    {
        return None;
    }
    let mut bytes = vec![0u16; (size as usize).div_ceil(2)];
    let result = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null(),
            &mut kind,
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result != ERROR_SUCCESS || (size as usize) > bytes.len() * 2 {
        return None;
    }
    let chars = &bytes[..(size as usize) / 2];
    let end = chars.iter().position(|x| *x == 0).unwrap_or(chars.len());
    String::from_utf16(&chars[..end]).ok()
}

#[cfg(windows)]
fn registry_config(guid: &str, ipv6: bool) -> (String, String) {
    let service = if ipv6 { "Tcpip6" } else { "Tcpip" };
    let registry_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters\\Interfaces\\{{{guid}}}"
    );
    let path = wide(&registry_path);
    let mut key: HKEY = null_mut();
    let error = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if error != ERROR_SUCCESS {
        return (String::new(), String::new());
    }
    let manual = registry_value(key, "NameServer").unwrap_or_default();
    let dhcp = registry_value(key, "DhcpNameServer").unwrap_or_default();
    unsafe { RegCloseKey(key) };
    (manual, dhcp)
}

fn parse_dns_list(text: &str, ipv6: bool) -> Option<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for raw in text
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let address: IpAddr = raw.parse().ok()?;
        if address.is_ipv6() != ipv6 {
            return None;
        }
        addresses.push(address);
    }
    Some(addresses)
}

fn infer_mode(manual: &str, dhcp: &str, effective: &[IpAddr], ipv6: bool) -> &'static str {
    let Some(static_addresses) = parse_dns_list(manual, ipv6) else {
        return "Unknown";
    };
    if !static_addresses.is_empty() {
        return if same_addresses(&static_addresses, effective) {
            "Static"
        } else {
            "Unknown"
        };
    }
    let Some(dhcp_addresses) = parse_dns_list(dhcp, ipv6) else {
        return "Unknown";
    };
    if same_addresses(&dhcp_addresses, effective) && !effective.is_empty() {
        "DHCP"
    } else {
        "Unknown"
    }
}

#[cfg(windows)]
unsafe fn read_adapter(node: &IP_ADAPTER_ADDRESSES_LH) -> Result<Adapter, DnsError> {
    let guid = unsafe { CStr::from_ptr(node.AdapterName.cast()) }
        .to_str()
        .map_err(|e| DnsError::Invalid(e.to_string()))?
        .trim_matches(|ch| ch == '{' || ch == '}')
        .to_lowercase();
    if !valid_guid(&guid) {
        return Err(DnsError::Invalid(
            "Windows returned an invalid interface GUID.".into(),
        ));
    }
    let v4_index = unsafe { node.Anonymous1.Anonymous.IfIndex };
    let v6_index = node.Ipv6IfIndex;
    let mut ipv4 = Family {
        available: v4_index > 0,
        ..Default::default()
    };
    let mut ipv6 = Family {
        available: v6_index > 0,
        ..Default::default()
    };
    let mut cursor = node.FirstDnsServerAddress;
    let mut iterations = 0;
    while !cursor.is_null() && iterations < 128 {
        let entry = unsafe { &*cursor };
        if let Some(ip) = unsafe { socket_ip(&entry.Address) } {
            let bucket = if ip.is_ipv6() { &mut ipv6 } else { &mut ipv4 };
            if !bucket.servers.contains(&ip) {
                bucket.servers.push(ip);
            }
        }
        cursor = entry.Next;
        iterations += 1;
    }
    let (manual4, dhcp4) = registry_config(&guid, false);
    let (manual6, dhcp6) = registry_config(&guid, true);
    ipv4.mode = infer_mode(&manual4, &dhcp4, &ipv4.servers, false).to_string();
    ipv6.mode = infer_mode(&manual6, &dhcp6, &ipv6.servers, true).to_string();
    let index = if v4_index > 0 { v4_index } else { v6_index };
    Ok(Adapter {
        guid,
        index,
        name: unsafe { decode_wide(node.FriendlyName) },
        description: unsafe { decode_wide(node.Description) },
        status: if node.OperStatus == IfOperStatusUp {
            "Up"
        } else {
            "Down"
        }
        .into(),
        physical: [IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211].contains(&node.IfType),
        ipv4,
        ipv6,
    })
}

#[cfg(windows)]
pub fn discover() -> Result<Vec<Adapter>, DnsError> {
    // IP Helper returns the required buffer length before writing anything.
    let mut size = 16_384u32;
    for _attempt in 0..4 {
        let mut memory = vec![0u64; (size as usize).div_ceil(8)];
        let mut reported = (memory.len() * 8) as u32;
        let first = memory.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                null(),
                first,
                &mut reported,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            size = reported.saturating_add(1024);
            continue;
        }
        if result != ERROR_SUCCESS {
            return Err(DnsError::Api(format!(
                "GetAdaptersAddresses failed: {result}"
            )));
        }
        let mut adapters = Vec::new();
        let mut current = first;
        for _ in 0..1024 {
            if current.is_null() {
                break;
            }
            let node = unsafe { &*current };
            // Some Windows adapter records expose only IPv6 index.
            let index = unsafe { node.Anonymous1.Anonymous.IfIndex };
            if index > 0 || node.Ipv6IfIndex > 0 {
                adapters.push(unsafe { read_adapter(node) }?);
            }
            current = node.Next;
        }
        adapters.sort_by(|a, b| {
            let up = |adapter: &Adapter| adapter.status.eq_ignore_ascii_case("Up");
            up(b)
                .cmp(&up(a))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        return Ok(adapters);
    }
    Err(DnsError::Api(
        "Windows adapter inventory repeatedly changed size.".into(),
    ))
}

#[cfg(not(windows))]
pub fn discover() -> Result<Vec<Adapter>, DnsError> {
    Err(DnsError::Unsupported)
}

#[cfg(windows)]
fn set_dns(guid: &str, ipv6: bool, addresses: &[IpAddr], automatic: bool) -> Result<(), DnsError> {
    let identity = parse_guid(guid)?;
    let prepared = if automatic {
        String::new()
    } else {
        addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut wide_addresses = wide(&prepared);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | if ipv6 { DNS_SETTING_IPV6 } else { 0 }) as u64,
        // An empty NameServer with DNS_SETTING_NAMESERVER clears static DNS and
        // restores the interface's network-provided resolver list.
        NameServer: wide_addresses.as_mut_ptr(),
        Domain: null_mut(),
        SearchList: null_mut(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: null_mut(),
    };
    let error = unsafe { SetInterfaceDnsSettings(identity, &settings) };
    if error != ERROR_SUCCESS {
        return Err(DnsError::Api(format!(
            "SetInterfaceDnsSettings({}) failed with Windows error {error}",
            if ipv6 { "IPv6" } else { "IPv4" }
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn rollback(guid: &str, ipv6: bool, original: &Family) -> Result<(), DnsError> {
    match original.mode.as_str() {
        "DHCP" => set_dns(guid, ipv6, &[], true),
        "Static" if !original.servers.is_empty() => set_dns(guid, ipv6, &original.servers, false),
        _ => Err(DnsError::Verification(
            "Cannot restore an unverified prior DNS mode.".into(),
        )),
    }
}

fn satisfied(actual: &Family, wanted: &[IpAddr], automatic: bool) -> bool {
    if automatic {
        actual.mode == "DHCP"
    } else {
        actual.mode == "Static" && same_addresses(wanted, &actual.servers)
    }
}

/// A family without a usable interface or a verified previous DNS mode is
/// silently ignored; UI notifications should only describe real operations.
fn family_can_change(source: &Family) -> bool {
    source.available && matches!(source.mode.as_str(), "DHCP" | "Static")
}

#[cfg(windows)]
struct Operation {
    ipv6: bool,
    original: Family,
    desired: Vec<IpAddr>,
}

#[cfg(windows)]
fn find_adapter(guid: &str) -> Result<Adapter, DnsError> {
    discover()?
        .into_iter()
        .find(|adapter| adapter.guid.eq_ignore_ascii_case(guid))
        .ok_or_else(|| DnsError::Invalid("Selected adapter is missing.".into()))
}

/// Apply exactly one immutable preset to exactly one selected Windows adapter.
/// Revalidate GUID/index/mode before mutation, and verify/rollback after it.
#[cfg(windows)]
pub fn switch(guid: &str, profile: &Profile) -> Result<String, DnsError> {
    if !crate::privilege::elevated() {
        return Err(DnsError::Invalid(
            "Administrator approval is required.".into(),
        ));
    }
    if !valid_guid(guid) {
        return Err(DnsError::Invalid("Invalid adapter GUID.".into()));
    }
    let target4 = profile_addresses(profile.ipv4, false)?;
    let target6 = profile_addresses(profile.ipv6, true)?;
    let before = find_adapter(guid)?;
    if before.index == 0 || !before.status.eq_ignore_ascii_case("Up") {
        return Err(DnsError::Invalid(
            "Selected adapter is disconnected.".into(),
        ));
    }
    let mut planned = Vec::new();
    let mut applicable = 0;
    for (ipv6, servers, source) in [
        (false, target4, &before.ipv4),
        (true, target6, &before.ipv6),
    ] {
        if !profile.automatic && servers.is_empty() {
            continue;
        }
        if !family_can_change(source) {
            continue;
        }
        applicable += 1;
        if !satisfied(source, &servers, profile.automatic) {
            planned.push(Operation {
                ipv6,
                original: source.clone(),
                desired: servers,
            });
        }
    }
    if applicable == 0 {
        return Err(DnsError::Invalid(
            "No DNS configuration can be verified on this adapter.".into(),
        ));
    }
    if planned.is_empty() {
        return Ok(format!("Already active on {}.", before.name));
    }
    let latest = find_adapter(guid)?;
    if latest.index != before.index
        || latest.status != before.status
        || latest.ipv4.mode != before.ipv4.mode
        || latest.ipv6.mode != before.ipv6.mode
        || latest.ipv4.servers != before.ipv4.servers
        || latest.ipv6.servers != before.ipv6.servers
    {
        return Err(DnsError::Invalid(
            "DNS or adapter changed. Refresh and retry.".into(),
        ));
    }

    let mut attempted: Vec<&Operation> = Vec::new();
    let result = (|| {
        for operation in &planned {
            attempted.push(operation);
            set_dns(guid, operation.ipv6, &operation.desired, profile.automatic)?;
        }
        let mut last_error = None;
        for _ in 0..5 {
            let after = find_adapter(guid)?;
            if after.index != before.index {
                return Err(DnsError::Verification(
                    "Network interface index changed.".into(),
                ));
            }
            if planned.iter().all(|operation| {
                let current = if operation.ipv6 {
                    &after.ipv6
                } else {
                    &after.ipv4
                };
                satisfied(current, &operation.desired, profile.automatic)
            }) {
                return Ok(());
            }
            last_error = Some(DnsError::Verification(
                "Windows DNS read-back did not match the requested policy.".into(),
            ));
            thread::sleep(Duration::from_millis(150));
        }
        Err(last_error.unwrap_or_else(|| DnsError::Verification("DNS verification failed.".into())))
    })();

    if let Err(error) = result {
        let problems: Vec<_> = attempted
            .iter()
            .rev()
            .filter_map(|item| rollback(guid, item.ipv6, &item.original).err())
            .map(|e| e.to_string())
            .collect();
        if !problems.is_empty() {
            return Err(DnsError::Verification(format!(
                "{error}; rollback incomplete ({}). Restore DNS manually.",
                problems.join("; ")
            )));
        }
        let recovered = find_adapter(guid).ok();
        let valid = recovered.as_ref().is_some_and(|adapter| {
            adapter.index == before.index
                && attempted.iter().all(|operation| {
                    let actual = if operation.ipv6 {
                        &adapter.ipv6
                    } else {
                        &adapter.ipv4
                    };
                    actual.mode == operation.original.mode
                        && same_addresses(&actual.servers, &operation.original.servers)
                })
        });
        return Err(DnsError::Verification(if valid {
            format!("{error}; original DNS settings restored.")
        } else {
            format!("{error}; rollback could not be verified. Restore DNS manually.")
        }));
    }

    Ok("DNS settings verified by Windows.".into())
}

#[cfg(not(windows))]
pub fn switch(_guid: &str, _profile: &Profile) -> Result<String, DnsError> {
    Err(DnsError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_adapter_guids_are_rejected() {
        assert!(valid_guid("{00112233-4455-6677-8899-aabbccddeeff}"));
        assert!(!valid_guid("Ethernet & calc"));
        assert!(!valid_guid("00112233-4455-6677-8899-aabbccddeezz"));
    }

    #[test]
    fn all_builtin_servers_match_their_address_families() {
        for profile in crate::profiles::BUILTIN_PROFILES {
            assert!(
                profile_addresses(profile.ipv4, false).is_ok(),
                "{}",
                profile.id
            );
            assert!(
                profile_addresses(profile.ipv6, true).is_ok(),
                "{}",
                profile.id
            );
        }
    }

    #[test]
    fn mode_requires_consistent_static_or_dhcp_read_back() {
        let resolver = vec!["1.1.1.1".parse().unwrap()];
        assert_eq!(infer_mode("1.1.1.1", "", &resolver, false), "Static");
        assert_eq!(infer_mode("", "1.1.1.1", &resolver, false), "DHCP");
        assert_eq!(infer_mode("8.8.8.8", "", &resolver, false), "Unknown");
        assert_eq!(infer_mode("", "", &resolver, false), "Unknown");
        assert_eq!(infer_mode("", "", &[], false), "Unknown");
        assert!(!satisfied(
            &Family {
                available: true,
                mode: "Unknown".into(),
                servers: resolver
            },
            &[],
            true
        ));
    }

    #[test]
    fn undiscovered_family_is_ignored_without_announcing_it() {
        let ready = Family {
            available: true,
            mode: "Static".into(),
            servers: vec!["1.1.1.1".parse().unwrap()],
        };
        let unavailable = Family {
            available: false,
            ..Default::default()
        };
        let unknown = Family {
            available: true,
            mode: "Unknown".into(),
            ..Default::default()
        };
        assert!(family_can_change(&ready));
        assert!(!family_can_change(&unavailable));
        assert!(!family_can_change(&unknown));
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_adapter_inventory_is_read_only() {
        let list = discover().expect("Native IP Helper adapter discovery must succeed");
        assert!(!list.is_empty());
        assert!(list.iter().all(|a| valid_guid(&a.guid) && a.index > 0));
        for nic in list
            .iter()
            .filter(|nic| nic.physical && nic.status == "Up")
            .take(3)
        {
            println!(
                "Native network inventory: {} IPv4={} IPv6={}",
                nic.name, nic.ipv4.mode, nic.ipv6.mode
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_dns_operations_are_unavailable() {
        assert!(matches!(discover(), Err(DnsError::Unsupported)));
    }
}
