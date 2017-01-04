//! All communications inside of the domain protocol are carried in a single
//! format called a message.  The top level format of message is divided
//! into 5 sections (some of which are empty in certain cases) shown below:
//!
//! ```text
//!     +---------------------+
//!     |        Header       |
//!     +---------------------+
//!     |       Question      | the question for the name server
//!     +---------------------+
//!     |        Answer       | RRs answering the question
//!     +---------------------+
//!     |      Authority      | RRs pointing toward an authority
//!     +---------------------+
//!     |      Additional     | RRs holding additional information
//!     +---------------------+
//! ```
//!
//! The header section is always present.  The header includes fields that
//! specify which of the remaining sections are present, and also specify
//! whether the message is a query or a response, a standard query or some
//! other opcode, etc.
//!
//! The header section format:
//!
//! ```text
//!                                     1  1  1  1  1  1
//!       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                      ID                       |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    QDCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ANCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    NSCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ARCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```
use std::env;
use std::fmt;
use std::fs::File;
use std::str::FromStr;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::{Cursor, Result, BufReader, BufRead};

use rand;

use network::*;
use super::{QType, QClass};

struct ResponseRecord(String, String, u16, u16);
struct ResponseHeader(u16, u16, u16, u16, u16, u16, u16, u16, u16);
pub struct Response {
    pub hostname: String,
    pub questions: Vec<(String, u16, u16)>,
    pub answers: Vec<(String, u16, u16)>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {:?}", self.hostname, self.answers)
    }
}

impl Response {
    fn new() -> Response {
        Response {
            hostname: String::new(),
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }
}

// For detail, see page 7 of RFC 1035
fn build_address(address: &str) -> Option<Vec<u8>> {
    let mut v = vec![];
    let bytes = address.as_bytes();
    for label in bytes.split(|ch| *ch == b'.') {
        match label.len() {
            0 => continue,
            n if n > 63 => return None,
            n => {
                v.push(n as u8);
                v.extend_from_slice(label);
            }
        }
    }

    v.push(0);
    Some(v)
}

// For detail, see page 24 of RFC 1035
pub fn build_request(address: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut r = vec![];
    // The header section:
    //
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |               random request_id               |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     | 0|     0     | 0| 0| 1| 0|   0    |     0     |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       1                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       0                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       0                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       0                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    let request_id = rand::random::<u16>();

    pack!(u16, r, request_id);
    pack!(u8, r, 1);
    pack!(u8, r, 0);
    pack!(u16, r, 1);
    pack!(u16, r, 0);
    pack!(u16, r, 0);
    pack!(u16, r, 0);
    // address
    let addr = try_opt!(build_address(address));
    r.extend(addr);
    // qtype and qclass
    pack!(u16, r, qtype);
    pack!(u16, r, QClass::IN);

    Some(r)
}

// RDATA: a variable length string of octets that describes the resource.
//        The format of this information varies according to the TYPE and CLASS
//        of the resource record. For example, the if the TYPE is A
//        and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
fn parse_ip(addrtype: u16, data: &[u8], length: usize, offset: usize) -> Option<String> {
    let ip_part = &data[offset..offset + length];

    match addrtype {
        QType::A => slice2ip4(ip_part),
        QType::AAAA => slice2ip6(ip_part),
        QType::CNAME | QType::NS => Some(try_opt!(parse_name(data, offset as u16)).1),
        _ => slice2string(ip_part),
    }
}

// For detail, see page 29 of RFC 1035
fn parse_name(data: &[u8], offset: u16) -> Option<(u16, String)> {
    let mut p = offset as usize;
    let mut l = data[p];
    let mut labels: Vec<String> = Vec::new();

    while l > 0 {
        // if compressed
        if (l & 0b11000000) == 0b11000000 {
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //    | 1  1|                OFFSET                   |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            let mut tmp = Cursor::new(&data[p..p + 2]);
            let mut ptr = unpack!(u16, tmp);
            ptr &= 0x3FFF;
            let r = try_opt!(parse_name(data, ptr));
            labels.push(r.1);
            p += 2;
            return Some((p as u16 - offset, labels.join(".")));
        } else {
            labels.push(try_opt!(slice2string(&data[(p + 1)..(p + 1 + l as usize)])));
            p += 1 + l as usize;
        }

        l = data[p];
    }

    Some((p as u16 + 1 - offset, labels.join(".")))
}

// For detail, see page 27, 28 of RFC 1035
fn parse_record(data: &[u8], offset: u16, question: bool) -> Option<(u16, ResponseRecord)> {
    let (nlen, name) = try_opt!(parse_name(data, offset));

    // The question section format:
    //
    //                                     1  1  1  1  1  1
    //       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                                               |
    //     /                     QNAME                     /
    //     /                                               /
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                     QTYPE                     |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                     QCLASS                    |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    if question {
        let bytes = &data[(offset + nlen) as usize..(offset + nlen + 4) as usize];
        let mut record = Cursor::new(bytes);

        let record_type = unpack!(u16, record);
        let record_class = unpack!(u16, record);

        Some((nlen + 4, ResponseRecord(name, String::new(), record_type, record_class)))
        //                                    1  1  1  1  1  1
        //      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                                               |
        //    /                                               /
        //    /                      NAME                     /
        //    |                                               |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                      TYPE                     |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                     CLASS                     |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                      TTL                      |
        //    |                                               |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                   RDLENGTH                    |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        //    /                     RDATA                     /
        //    /                                               /
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    } else {
        let bytes = &data[(offset + nlen) as usize..(offset + nlen + 10) as usize];
        let mut record = Cursor::new(bytes);

        let record_type = unpack!(u16, record);
        let record_class = unpack!(u16, record);
        let _record_ttl = unpack!(u32, record);
        let record_rdlength = unpack!(u16, record);

        // RDATA
        let ip = try_opt!(parse_ip(record_type,
                                   data,
                                   record_rdlength as usize,
                                   (offset + nlen + 10) as usize));

        Some((nlen + 10 + record_rdlength, ResponseRecord(name, ip, record_type, record_class)))
    }
}

fn parse_header(data: &[u8]) -> Option<ResponseHeader> {
    if data.len() < 12 {
        return None;
    }

    let mut header = Cursor::new(data);

    let id = unpack!(u16, header);
    let byte3 = unpack!(u8, header);
    let byte4 = unpack!(u8, header);
    let qdcount = unpack!(u16, header);
    let ancount = unpack!(u16, header);
    let nscount = unpack!(u16, header);
    let arcount = unpack!(u16, header);
    let qr = (byte3 & 0b10000000) as u16;
    let tc = (byte3 & 0b00000010) as u16;
    let ra = (byte4 & 0b00000010) as u16;
    let rcode = (byte4 & 0b00001111) as u16;

    Some(ResponseHeader(id, qr, tc, ra, rcode, qdcount, ancount, nscount, arcount))
}

fn parse_records(data: &[u8],
                 offset: u16,
                 count: u16,
                 question: bool)
                 -> Option<(u16, Vec<ResponseRecord>)> {
    let mut records: Vec<ResponseRecord> = Vec::new();
    let mut offset = offset;

    for _i in 0..count {
        let (len, record) = try_opt!(parse_record(data, offset, question));
        offset += len;
        records.push(record);
    }

    Some((offset, records))
}

pub fn parse_response(data: &[u8]) -> Option<Response> {
    if data.len() < 12 {
        return None;
    }

    parse_header(data).and_then(|header| {
        let ResponseHeader(_id, _qr, _tc, _ra, _rcode, qdcount, ancount, _nscount, _arcount) =
            header;

        let offset = 12u16;
        let (offset, qds) = try_opt!(parse_records(data, offset, qdcount, true));
        let (_offset, ans) = try_opt!(parse_records(data, offset, ancount, false));
        // We don't need to parse the authority records and the additional records
        let (_offset, _nss) = try_opt!(parse_records(data, _offset, _nscount, false));
        let (_offset, _ars) = try_opt!(parse_records(data, _offset, _arcount, false));

        let mut response = Response::new();
        if !qds.is_empty() {
            response.hostname = qds[0].0.clone();
        }
        for an in qds {
            response.questions.push((an.1, an.2, an.3))
        }
        for an in ans {
            response.answers.push((an.1, an.2, an.3))
        }

        Some(response)
    })
}

pub fn parse_resolv(prefer_ipv6: bool) -> Vec<String> {
    let mut servers = vec![];

    let _ = handle_every_line("/etc/resolv.conf",
                              &mut |line| {
        if line.starts_with("nameserver") {
            if let Some(ip) = line.split_whitespace().nth(1) {
                if (prefer_ipv6 && is_ipv6(ip)) || (!prefer_ipv6 && is_ipv4(ip)) {
                    servers.push(ip.to_string());
                }
            }
        }
    });

    if servers.is_empty() {
        let dns_servers = if cfg!(feature = "china_dns") {
            vec!["114.114.114.114", "114.114.115.115"]
        } else {
            if prefer_ipv6 {
                vec!["2001:4860:4860::8888", "2001:4860:4860::8844"]
            } else {
                vec!["8.8.8.8", "8.8.4.4"]
            }
        };

        servers = dns_servers.into_iter().map(|s| s.to_string()).collect();
    }

    servers
}


pub fn parse_hosts(prefer_ipv6: bool) -> HashMap<String, IpAddr> {
    let mut hosts = HashMap::new();
    let localhost = if prefer_ipv6 {
        IpAddr::V6(Ipv6Addr::from_str("::1").unwrap())
    } else {
        IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap())
    };
    hosts.insert("localhost".to_string(), localhost);

    let hosts_path = if cfg!(target_family = "UNIX") {
        PathBuf::from("/etc/hosts")
    } else {
        let mut path = match env::var("WINDIR") {
            Ok(dir) => PathBuf::from(dir),
            _ => return hosts,
        };
        path.push("/system32/drivers/etc/hosts");
        path
    };

    let _ = handle_every_line(&hosts_path,
                              &mut |line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() {
            let ip_addr = str2ipaddr(parts[0], prefer_ipv6);

            if let Some(ip_addr) = ip_addr {
                for hostname in parts[1..].iter() {
                    if !hostname.is_empty() {
                        hosts.insert(hostname.to_string(), ip_addr);
                    }
                }
            }
        }
    });

    hosts
}

fn handle_every_line<P: AsRef<Path>>(filepath: P, func: &mut FnMut(String)) -> Result<()> {
    let f = File::open(filepath)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line.trim().to_string(),
            _ => break,
        };

        func(line);
    }
    Ok(())
}

fn slice2string(data: &[u8]) -> Option<String> {
    String::from_utf8(data.to_vec()).ok()
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn parse_response() {
        let data: &[u8] =
            &[0x0d, 0x0d, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x05, 0x62,
              0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
              0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0xb4, 0x95, 0x84,
              0x2f, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0xdc,
              0xb5, 0x39, 0xd9, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00,
              0x04, 0x6f, 0x0d, 0x65, 0xd0, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
              0x36, 0x00, 0x04, 0x7b, 0x7d, 0x72, 0x90, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00,
              0x01, 0x4f, 0x30, 0x00, 0x06, 0x03, 0x64, 0x6e, 0x73, 0xc0, 0x0c, 0xc0, 0x0c, 0x00,
              0x02, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x30, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x37, 0xc0,
              0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x30, 0x00, 0x06, 0x03,
              0x6e, 0x73, 0x33, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x4f,
              0x30, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00,
              0x01, 0x00, 0x01, 0x4f, 0x30, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c];

        assert!(super::parse_response(data).is_some());
    }
}
