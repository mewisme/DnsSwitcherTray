//! Immutable DNS provider catalog owned by the standalone Rust application.
//!
//! IPv4/IPv6 addresses are paired by the same provider and filtering policy.
//! Sources: https://adguard-dns.io/en/public-dns.html
//! https://docs.controld.com/docs/free-dns
//! https://cleanbrowsing.org/support/troubleshooting/command-line-dns
//! https://support.opendns.com/
//!
//! This catalog is Rust source, not a generated translation from another
//! language. No profile file, editor, or user-provided resolver is accepted.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub id: &'static str,
    pub name: &'static str,
    pub ipv4: &'static [&'static str],
    pub ipv6: &'static [&'static str],
    pub automatic: bool,
}

pub static BUILTIN_PROFILES: &[Profile] = &[
    Profile {
        id: "automatic",
        name: "Automatic",
        ipv4: &[],
        ipv6: &[],
        automatic: true,
    },
    Profile {
        id: "cloudflare",
        name: "Cloudflare",
        ipv4: &["1.1.1.1", "1.0.0.1"],
        ipv6: &["2606:4700:4700::1111", "2606:4700:4700::1001"],
        automatic: false,
    },
    Profile {
        id: "google",
        name: "Google",
        ipv4: &["8.8.8.8", "8.8.4.4"],
        ipv6: &["2001:4860:4860::8888", "2001:4860:4860::8844"],
        automatic: false,
    },
    Profile {
        id: "quad9",
        name: "Quad9",
        ipv4: &["9.9.9.9", "149.112.112.112"],
        ipv6: &["2620:fe::fe", "2620:fe::9"],
        automatic: false,
    },
    Profile {
        id: "adguard",
        name: "AdGuard DNS",
        ipv4: &["94.140.14.14", "94.140.15.15"],
        ipv6: &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        automatic: false,
    },
    Profile {
        id: "adguard-unfiltered",
        name: "AdGuard DNS (Unfiltered)",
        ipv4: &["94.140.14.140", "94.140.14.141"],
        ipv6: &["2a10:50c0::1:ff", "2a10:50c0::2:ff"],
        automatic: false,
    },
    Profile {
        id: "adguard-family",
        name: "AdGuard DNS (Family)",
        ipv4: &["94.140.14.15", "94.140.15.16"],
        ipv6: &["2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
        automatic: false,
    },
    Profile {
        id: "opendns",
        name: "OpenDNS",
        ipv4: &["208.67.222.222", "208.67.220.220"],
        ipv6: &["2620:119:35::35", "2620:119:53::53"],
        automatic: false,
    },
    Profile {
        id: "opendns-family",
        name: "OpenDNS FamilyShield",
        ipv4: &["208.67.222.123", "208.67.220.123"],
        ipv6: &["2620:119:35::123", "2620:119:53::123"],
        automatic: false,
    },
    Profile {
        id: "controld",
        name: "Control D (Unfiltered)",
        ipv4: &["76.76.2.0", "76.76.10.0"],
        ipv6: &["2606:1a40::", "2606:1a40:1::"],
        automatic: false,
    },
    Profile {
        id: "controld-malware",
        name: "Control D (Malware)",
        ipv4: &["76.76.2.1", "76.76.10.1"],
        ipv6: &["2606:1a40::1", "2606:1a40:1::1"],
        automatic: false,
    },
    Profile {
        id: "controld-ads",
        name: "Control D (Ads & Tracking)",
        ipv4: &["76.76.2.2", "76.76.10.2"],
        ipv6: &["2606:1a40::2", "2606:1a40:1::2"],
        automatic: false,
    },
    Profile {
        id: "controld-family",
        name: "Control D (Family)",
        ipv4: &["76.76.2.4", "76.76.10.4"],
        ipv6: &["2606:1a40::4", "2606:1a40:1::4"],
        automatic: false,
    },
    Profile {
        id: "cleanbrowsing-security",
        name: "CleanBrowsing (Security)",
        ipv4: &["185.228.168.9", "185.228.169.9"],
        ipv6: &["2a0d:2a00:1::2", "2a0d:2a00:2::2"],
        automatic: false,
    },
    Profile {
        id: "cleanbrowsing-adult",
        name: "CleanBrowsing (Adult)",
        ipv4: &["185.228.168.10", "185.228.169.11"],
        ipv6: &["2a0d:2a00:1::1", "2a0d:2a00:2::1"],
        automatic: false,
    },
    Profile {
        id: "cleanbrowsing-family",
        name: "CleanBrowsing (Family)",
        ipv4: &["185.228.168.168", "185.228.169.168"],
        ipv6: &["2a0d:2a00:1::", "2a0d:2a00:2::"],
        automatic: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn all_builtin_profiles_have_valid_unique_addresses() {
        assert_eq!(BUILTIN_PROFILES.len(), 16);
        assert_eq!(BUILTIN_PROFILES[0].id, "automatic");
        assert!(BUILTIN_PROFILES[0].automatic);
        assert!(BUILTIN_PROFILES[0].ipv4.is_empty());
        assert!(BUILTIN_PROFILES[0].ipv6.is_empty());

        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for p in BUILTIN_PROFILES {
            assert!(ids.insert(p.id), "duplicate profile ID: {}", p.id);
            assert!(names.insert(p.name), "duplicate profile name: {}", p.name);
            if p.automatic {
                continue;
            }
            assert_eq!(p.ipv4.len(), 2, "{} IPv4 addresses", p.id);
            assert_eq!(p.ipv6.len(), 2, "{} IPv6 addresses", p.id);
            assert_ne!(p.ipv4[0], p.ipv4[1]);
            assert_ne!(p.ipv6[0], p.ipv6[1]);
            for ip in p.ipv4 {
                let address = ip.parse::<Ipv4Addr>().expect("invalid provider IPv4");
                assert!(!address.is_unspecified() && !address.is_multicast());
            }
            for ip in p.ipv6 {
                let address = ip.parse::<Ipv6Addr>().expect("invalid provider IPv6");
                assert!(!address.is_unspecified() && !address.is_multicast());
            }
        }
    }

    #[test]
    fn major_providers_and_family_variants_are_available() {
        for id in [
            "cloudflare",
            "google",
            "quad9",
            "adguard",
            "adguard-unfiltered",
            "adguard-family",
            "opendns",
            "opendns-family",
            "controld",
            "controld-malware",
            "controld-ads",
            "controld-family",
            "cleanbrowsing-security",
            "cleanbrowsing-adult",
            "cleanbrowsing-family",
        ] {
            assert!(
                BUILTIN_PROFILES.iter().any(|profile| profile.id == id),
                "{id}"
            );
        }
    }
}
