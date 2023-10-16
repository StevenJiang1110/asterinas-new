use smoltcp::wire::Ipv4Address;

use crate::net::get_localhost_iface;
use crate::net::get_virtio_iface;
use crate::net::iface::BindConfig;
use crate::net::iface::Iface;
use crate::net::iface::{AnyBoundSocket, AnyUnboundSocket};
use crate::net::iface::{IpAddress, IpEndpoint};
use crate::net::IFACES;
use crate::prelude::*;

pub fn get_iface_to_bind(ip_addr: &IpAddress) -> Option<Arc<dyn Iface>> {
    let IpAddress::Ipv4(ipv4_addr) = ip_addr else {
        todo!("support ipv6");
    };

    if *ipv4_addr == Ipv4Address::UNSPECIFIED {
        // FIXME: this is a temporary solution, we bind `0.0.0.0` to localhost iface.
        return Some(get_localhost_iface());
    }

    let ifaces = IFACES.get().unwrap();
    ifaces
        .iter()
        .find(|iface| {
            if let Some(iface_ipv4_addr) = iface.ipv4_addr() {
                iface_ipv4_addr == *ipv4_addr
            } else {
                false
            }
        })
        .map(Clone::clone)
}

/// Get a suitable iface to deal with sendto/connect request if the socket is not bound to an iface.
/// If the remote address is the same as that of some iface, we will use the iface.
/// Otherwise, we will use a default interface.
fn get_ephemeral_iface(remote_ip_addr: &IpAddress) -> Arc<dyn Iface> {
    let IpAddress::Ipv4(remote_ipv4_addr) = remote_ip_addr else {
        todo!("support ipv6")
    };

    if *remote_ipv4_addr == Ipv4Address::UNSPECIFIED {
        // FIXME: this is a temporary solution, we bind `0.0.0.0` to localhost iface.
        return get_localhost_iface();
    }

    let ifaces = IFACES.get().unwrap();
    if let Some(iface) = ifaces.iter().find(|iface| {
        if let Some(iface_ipv4_addr) = iface.ipv4_addr() {
            iface_ipv4_addr == *remote_ipv4_addr
        } else {
            false
        }
    }) {
        return iface.clone();
    }
    // FIXME: use the virtio-net as the default interface
    get_virtio_iface()
}

/// For tcp socket, it can bind to empheral port. i.e., the port is zero and kernel
/// picks up an random unused port for it.
/// For udp socket, the port must be a non-zero value.
pub(super) fn bind_socket(
    unbound_socket: AnyUnboundSocket,
    endpoint: IpEndpoint,
    reuse_port: bool,
    is_empheral_port: bool,
) -> core::result::Result<Arc<AnyBoundSocket>, (Error, AnyUnboundSocket)> {
    let iface = match get_iface_to_bind(&endpoint.addr) {
        Some(iface) => iface,
        None => {
            let err = Error::with_message(Errno::EADDRNOTAVAIL, "Request iface is not available");
            return Err((err, unbound_socket));
        }
    };
    let bind_config = match BindConfig::new(endpoint, reuse_port, is_empheral_port) {
        Ok(config) => config,
        Err(e) => return Err((e, unbound_socket)),
    };
    iface.bind_socket(unbound_socket, bind_config)
}

pub fn get_ephemeral_endpoint(remote_endpoint: &IpEndpoint) -> IpEndpoint {
    let iface = get_ephemeral_iface(&remote_endpoint.addr);
    let ip_addr = iface.ipv4_addr().unwrap();
    IpEndpoint::new(IpAddress::Ipv4(ip_addr), 0)
}
