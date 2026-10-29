//! Penolakan alamat jaringan privat untuk DAST (keputusan produk: tidak ada pemindaian jaringan internal).
//! Pemeriksaan dilakukan pada alamat hasil resolusi, termasuk pada tiap redirect, dan koneksi
//! hanya dibuka ke alamat yang sudah lolos (lewat resolver khusus), sehingga DNS rebinding tidak lolos.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

fn blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, termasuk metadata cloud 169.254.169.254
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmark 198.18.0.0/15
        || o[0] >= 240 // dicadangkan
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return blocked_v4(v4);
    }
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // dokumentasi
        || (seg[0] == 0x0064 && seg[1] == 0xff9b) // NAT64 64:ff9b::/96
}

fn hard_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // Endpoint layanan cloud (metadata, DNS, NTP, ECS) di dalam link-local: 169.254.169.0/24 dan 169.254.170.0/24.
    (o[0] == 169 && o[1] == 254 && (o[2] == 169 || o[2] == 170))
        || ip == Ipv4Addr::new(100, 100, 100, 200) // metadata Alibaba Cloud (di dalam CGNAT)
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || o[0] >= 240
}

fn hard_blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return hard_blocked_v4(v4);
    }
    let seg = ip.segments();
    ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] == 0xfd00 && seg[1] == 0x0ec2) // metadata AWS IPv6 fd00:ec2::/32 (di dalam ULA)
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        || (seg[0] == 0x0064 && seg[1] == 0xff9b)
}

/// Alamat yang TETAP ditolak walau jaringan privat diizinkan: endpoint metadata/layanan cloud
/// (169.254.169.0/24, 169.254.170.0/24, 100.100.100.200, fd00:ec2::/32), tidak terspesifikasi,
/// multicast, dan rentang cadangan. Seluruh jaringan privat (loopback, RFC1918, CGNAT, ULA,
/// link-local) dibolehkan.
pub fn is_hard_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => hard_blocked_v4(v4),
        IpAddr::V6(v6) => hard_blocked_v6(v6),
    }
}

/// Kebijakan alamat untuk koneksi DAST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Default: semua alamat privat, loopback, link-local, dan metadata ditolak.
    Strict,
    /// Semua jaringan privat (loopback, RFC1918, CGNAT, ULA, link-local) diizinkan; endpoint metadata cloud tetap ditolak.
    AllowPrivate,
    /// Hanya untuk pengujian: tidak ada pembatasan.
    AllowAll,
}

impl Policy {
    pub fn blocks(self, ip: IpAddr) -> bool {
        match self {
            Policy::Strict => is_blocked(ip),
            Policy::AllowPrivate => is_hard_blocked(ip),
            Policy::AllowAll => false,
        }
    }
}

/// True bila alamat termasuk loopback, link-local, metadata, privat, CGNAT, ULA, atau rentang cadangan.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

/// Resolver yang menolak seluruh hasil bila ada satu alamat terlarang.
#[derive(Debug, Clone, Copy)]
pub struct GuardedResolver {
    pub policy: Policy,
}

impl Resolver for GuardedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addrs = DefaultResolver::default().resolve(uri, config, timeout)?;
        if let Some(bad) = addrs.iter().find(|a| self.policy.blocks(a.ip())) {
            return Err(ureq::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("alamat jaringan privat tidak diizinkan: {}", bad.ip()),
            )));
        }
        Ok(addrs)
    }
}

pub fn blocked_addr(addr: &SocketAddr) -> bool {
    is_blocked(addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_blocked(s.parse().unwrap())
    }

    #[test]
    fn blocks_every_private_class() {
        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "ff02::1",
        ] {
            assert!(blocked(ip), "{ip} harus ditolak");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(!blocked(ip), "{ip} seharusnya diizinkan");
        }
    }

    #[test]
    fn allow_private_keeps_cloud_metadata_endpoints_blocked() {
        let p = Policy::AllowPrivate;
        for ip in [
            "169.254.169.254",
            "169.254.169.253",
            "169.254.170.2",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            assert!(p.blocks(ip.parse().unwrap()), "{ip} harus tetap ditolak");
        }
        for ip in [
            "169.254.1.1",
            "169.254.10.20",
            "fe80::1",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.5",
            "192.168.1.10",
            "100.64.0.1",
            "fd12:3456::1",
            "::1",
            "8.8.8.8",
        ] {
            assert!(!p.blocks(ip.parse().unwrap()), "{ip} harus diizinkan");
        }
    }

    #[test]
    fn strict_and_allow_all_policies() {
        assert!(Policy::Strict.blocks("10.0.0.1".parse().unwrap()));
        assert!(!Policy::Strict.blocks("8.8.8.8".parse().unwrap()));
        assert!(!Policy::AllowAll.blocks("169.254.169.254".parse().unwrap()));
    }
}
