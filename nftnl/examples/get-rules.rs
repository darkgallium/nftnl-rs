use ipnetwork::{IpNetwork, Ipv4Network};
use nftnl::{nft_expr, rule, nftnl_sys::libc, Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table};
use std::{
    ffi::{self, CString},
    io,
    net::Ipv4Addr,
};

fn main() -> Result<(), Error> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    
    let get_tables_msg = rules::get_rules_nlmsg(0);
    socket.send(&get_tables_msg)?;

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run2(message, 0, portid, rule::get_rules_cb)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }

    Ok(())
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
struct Error(String);

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error(error.to_string())
    }
}

impl From<ffi::NulError> for Error {
    fn from(error: ffi::NulError) -> Self {
        Error(error.to_string())
    }
}

impl From<ipnetwork::IpNetworkError> for Error {
    fn from(error: ipnetwork::IpNetworkError) -> Self {
        Error(error.to_string())
    }
}
