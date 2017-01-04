use std::io;
use std::str;
use std::io::Cursor;
use std::str::FromStr;
use std::convert::From;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

macro_rules! slice2sized {
    ($bytes:expr, $l: expr) => (
        {
            let mut arr = [0u8; $l];
            for i in 0..$bytes.len() {
                arr[i] = $bytes[i];
            }

            arr
        }
    )
}

pub fn is_ipv4(ip: &str) -> bool {
    Ipv4Addr::from_str(ip).is_ok()
}

pub fn is_ipv6(ip: &str) -> bool {
    Ipv6Addr::from_str(ip).is_ok()
}

pub fn is_ip(ip: &str) -> bool {
    is_ipv4(ip) || is_ipv6(ip)
}

pub fn str2ipaddr(ip: &str, prefer_ipv6: bool) -> Option<IpAddr> {
    if prefer_ipv6 {
        let addr = Ipv6Addr::from_str(ip);
        match addr {
            Ok(addr) => Some(IpAddr::V6(addr)),
            Err(_) => Ipv4Addr::from_str(ip).ok().map(IpAddr::V4),
        }
    } else {
        let addr = Ipv4Addr::from_str(ip);
        match addr {
            Ok(addr) => Some(IpAddr::V4(addr)),
            Err(_) => Ipv6Addr::from_str(ip).ok().map(IpAddr::V6),
        }
    }
}

// For detail, see page 7 of RFC 1035
pub fn is_hostname(hostname: &str) -> bool {
    if hostname.len() > 255 {
        return false;
    }

    let is_valid = |s: &str| {
        s.as_bytes().iter().all(|&c| {
            (b'0' <= c && c <= b'9') || (b'a' <= c && c <= b'z') || (b'A' <= c && c <= b'Z') ||
            (c == b'-')
        })
    };

    let hostname = hostname.trim_right_matches('.');
    hostname.as_bytes()
        .split(|c| *c == b'.')
        .all(|s| {
            let s = str::from_utf8(s).ok().unwrap_or("");
            !s.is_empty() && !s.starts_with('-') && !s.ends_with('-') && is_valid(s)
        })
}

pub fn slice2ip4(data: &[u8]) -> Option<String> {
    if data.len() >= 4 {
        Some(format!("{}", Ipv4Addr::from(slice2sized!(data, 4))))
    } else {
        None
    }
}

pub fn slice2ip6(data: &[u8]) -> Option<String> {
    if data.len() >= 16 {
        Some(format!("{}", Ipv6Addr::from(slice2sized!(data, 16))))
    } else {
        None
    }
}

pub fn pair2addr4(ip: &str, port: u16) -> io::Result<SocketAddr> {
    match Ipv4Addr::from_str(ip) {
        Ok(addr) => Ok(SocketAddr::new(IpAddr::V4(addr), port)),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

pub fn pair2addr6(ip: &str, port: u16) -> io::Result<SocketAddr> {
    match Ipv6Addr::from_str(ip) {
        Ok(addr) => Ok(SocketAddr::new(IpAddr::V6(addr), port)),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

pub fn pair2addr(ip: &str, port: u16) -> io::Result<SocketAddr> {
    pair2addr4(ip, port).or(pair2addr6(ip, port))
}

pub trait NetworkWriteBytes: WriteBytesExt {
    fn put_u8(&mut self, num: u8) -> io::Result<()> {
        self.write_u8(num)
    }

    fn put_u16(&mut self, num: u16) -> io::Result<()> {
        self.write_u16::<NetworkEndian>(num)
    }

    fn put_i32(&mut self, num: i32) -> io::Result<()> {
        self.write_i32::<NetworkEndian>(num)
    }
}

impl NetworkWriteBytes for Vec<u8> {}

pub trait NetworkReadBytes: ReadBytesExt {
    fn get_u8(&mut self) -> io::Result<u8> {
        self.read_u8()
    }

    fn get_u16(&mut self) -> io::Result<u16> {
        self.read_u16::<NetworkEndian>()
    }

    fn get_u32(&mut self) -> io::Result<u32> {
        self.read_u32::<NetworkEndian>()
    }
}

impl<'a> NetworkReadBytes for Cursor<&'a [u8]> {}
impl<'a> NetworkReadBytes for Cursor<&'a Vec<u8>> {}

impl<'a> NetworkReadBytes for &'a [u8] {
    fn get_u8(&mut self) -> io::Result<u8> {
        Cursor::new(self).read_u8()
    }

    fn get_u16(&mut self) -> io::Result<u16> {
        Cursor::new(self).read_u16::<NetworkEndian>()
    }

    fn get_u32(&mut self) -> io::Result<u32> {
        Cursor::new(self).read_u32::<NetworkEndian>()
    }
}

#[macro_export]
macro_rules! pack {
    (i32, $r:expr, $v:expr) => ( try_opt!($r.put_i32($v).ok()) );
    (u16, $r:expr, $v:expr) => ( try_opt!($r.put_u16($v).ok()) );
    (u8, $r:expr, $v:expr) => ( try_opt!($r.put_u8($v).ok()) );
}

#[macro_export]
macro_rules! unpack {
    (u32, $r:expr) => ( try_opt!($r.get_u32().ok()) );
    (u16, $r:expr) => ( try_opt!($r.get_u16().ok()) );
    (u8, $r:expr) => ( try_opt!($r.get_u8().ok()) );
}

#[macro_export]
macro_rules! try_pack {
    (i32, $r:expr, $v:expr) => ( $r.put_i32($v)? );
    (u16, $r:expr, $v:expr) => ( $r.put_u16($v)? );
    (u8, $r:expr, $v:expr) => ( $r.put_u8($v)? );
}

#[macro_export]
macro_rules! try_unpack {
    (u32, $r:expr) => ( $r.get_u32()? );
    (u16, $r:expr) => ( $r.get_u16()? );
    (u8, $r:expr) => ( $r.get_u8()? );
}
