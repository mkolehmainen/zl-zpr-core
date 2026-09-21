//! Common definitions that have no more specific place to live.

use zerocopy::*;
use zpr::packet_info::L3Type;
use zpr_utils::net_defs;

/// Packet direction with respect to an interface.
/// Primary use is for constructing libpcap link-layer header.
#[derive(Copy, Clone)]
pub enum Direction {
    // Do not change the values!  They are used directly to form the link-layer header.
    Inbound = 0,
    Outbound = 1,
}

/// IP 5-tuple used for hashing.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct FiveTuple {
    pub src_address: net_defs::IpAddress,
    pub dst_address: net_defs::IpAddress,
    pub l3_type: L3Type,
    pub l4_protocol: net_defs::IpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    #[allow(dead_code)]
    pub fn new(
        l3_type: L3Type,
        src_address: net_defs::IpAddress,
        dst_address: net_defs::IpAddress,
        l4_protocol: net_defs::IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_address,
            dst_address,
            l3_type,
            l4_protocol,
            src_port,
            dst_port,
        }
    }

    #[allow(dead_code)]
    pub fn reverse(&self) -> FiveTuple {
        Self {
            src_address: self.dst_address,
            dst_address: self.src_address,
            l3_type: self.l3_type,
            l4_protocol: self.l4_protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    pub fn set_src_address(&mut self, src_address: net_defs::IpAddress) {
        self.src_address = src_address;
    }
    pub fn set_dst_address(&mut self, dst_address: net_defs::IpAddress) {
        self.dst_address = dst_address;
    }
    pub fn set_l3_type(&mut self, l3_type: L3Type) {
        self.l3_type = l3_type;
    }
    pub fn set_l4_protocol(&mut self, l4_protocol: net_defs::IpProtocol) {
        self.l4_protocol = l4_protocol;
    }
    pub fn set_src_port(&mut self, src_port: u16) {
        self.src_port = src_port;
    }
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.dst_port = dst_port;
    }
}

impl From<zpr::vsapi_types::VsapiFiveTuple> for FiveTuple {
    fn from(other: zpr::vsapi_types::VsapiFiveTuple) -> Self {
        Self {
            src_address: other.source_addr.into(),
            dst_address: other.dest_addr.into(),
            l3_type: other.l3_type,
            l4_protocol: vsapi_ip_to_defs_ip(other.l4_protocol).unwrap(),
            src_port: other.source_port,
            dst_port: other.dest_port,
        }
    }
}

/// Translate a VSAPI IP protocol number into the local `net_defs::IpProtocol`
/// representation. Relocated from `zpr-utils::net_defs` (zipline#69): this is
/// its only caller, and keeping it here lets `zpr-utils` drop its dependency
/// on the `zpr` crate. Returns `Err` for any protocol outside the mapped set.
pub fn vsapi_ip_to_defs_ip(
    vsapi_proto: zpr::vsapi_types::VsapiIpProtocol,
) -> Result<net_defs::IpProtocol, &'static str> {
    use net_defs::ip_number;
    use zpr::vsapi_types::vsapi_ip_number;
    match vsapi_proto {
        vsapi_ip_number::HOPOPT => Ok(ip_number::HOPOPT),
        vsapi_ip_number::ICMP => Ok(ip_number::ICMP),
        vsapi_ip_number::IPINIP => Ok(ip_number::IPINIP),
        vsapi_ip_number::TCP => Ok(ip_number::TCP),
        vsapi_ip_number::UDP => Ok(ip_number::UDP),
        vsapi_ip_number::IPV6_ROUTE => Ok(ip_number::IPV6_ROUTE),
        vsapi_ip_number::IPV6_FRAG => Ok(ip_number::IPV6_FRAG),
        vsapi_ip_number::AH => Ok(ip_number::AH),
        vsapi_ip_number::IPV6_ICMP => Ok(ip_number::IPV6_ICMP),
        vsapi_ip_number::IPV6_OPTS => Ok(ip_number::IPV6_OPTS),
        _ => Err("Unknown protocol"),
    }
}

impl From<FiveTuple> for zpr::vsapi_types::VsapiFiveTuple {
    fn from(other: FiveTuple) -> Self {
        Self {
            source_addr: other.src_address.into(),
            dest_addr: other.dst_address.into(),
            l3_type: other.l3_type,
            l4_protocol: other.l4_protocol,
            source_port: other.src_port,
            dest_port: other.dst_port,
        }
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "({}, {}, {}, {}, {}, {})",
            self.l3_type,
            self.src_address,
            self.dst_address,
            self.l4_protocol,
            self.src_port,
            self.dst_port
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use zpr::vsapi_types::vsapi_ip_number;

    /// Pins the VSAPI-to-defs IP protocol mapping relocated from
    /// zpr-utils::net_defs (zipline#69): every mapped row must translate to
    /// the matching IANA protocol number, and an unmapped protocol must Err.
    #[test]
    fn vsapi_ip_to_defs_ip_maps_known_protocols() {
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::HOPOPT),
            Ok(net_defs::ip_number::HOPOPT)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::ICMP),
            Ok(net_defs::ip_number::ICMP)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::IPINIP),
            Ok(net_defs::ip_number::IPINIP)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::TCP),
            Ok(net_defs::ip_number::TCP)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::UDP),
            Ok(net_defs::ip_number::UDP)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::IPV6_ROUTE),
            Ok(net_defs::ip_number::IPV6_ROUTE)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::IPV6_FRAG),
            Ok(net_defs::ip_number::IPV6_FRAG)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::AH),
            Ok(net_defs::ip_number::AH)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::IPV6_ICMP),
            Ok(net_defs::ip_number::IPV6_ICMP)
        );
        assert_eq!(
            vsapi_ip_to_defs_ip(vsapi_ip_number::IPV6_OPTS),
            Ok(net_defs::ip_number::IPV6_OPTS)
        );
    }

    /// A VSAPI protocol number outside the mapped set must be rejected, not
    /// silently passed through.
    #[test]
    fn vsapi_ip_to_defs_ip_rejects_unknown_protocol() {
        // 253 is RFC 3692 "use for experimentation", not in the mapping.
        assert!(vsapi_ip_to_defs_ip(253).is_err());
    }
}
