use std::io;
use std::fmt;
use std::str::FromStr;
use std::convert::From;
use std::slice::from_raw_parts_mut;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs, SocketAddr};

use lru_cache::LruCache;
use mio::{Token, Ready, Poll, PollOpt};
use mio::udp::UdpSocket;

use network::*;
use parser::*;
use super::{QType, QClass};

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct HostIpaddr(pub String, pub IpAddr);

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ResolveResult {
    pub tokens: HashSet<Token>,
    pub result: HostIpaddr,
}

impl ResolveResult {
    fn new(tokens: HashSet<Token>, result: HostIpaddr) -> ResolveResult {
        ResolveResult {
            tokens: tokens,
            result: result,
        }
    }
}

const CACHE_SIZE: usize = 1024;
const BUF_SIZE: usize = 1024;

pub enum Error {
    TryAgain,
    Timeout,
    BufferEmpty,
    EmptyHostName,
    InvalidResponse,
    BuildRequestFailed,
    NoPreferredResponse,
    InvalidHost(String),
    UnknownHost(String),
    IO(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::TryAgain => write!(f, "try another QTYPE"),
            Error::Timeout => write!(f, "timeout"),
            Error::BufferEmpty => write!(f, "no buffered data available"),
            Error::EmptyHostName => write!(f, "empty hostname"),
            Error::InvalidResponse => write!(f, "invalid response"),
            Error::BuildRequestFailed => write!(f, "build dns request failed"),
            Error::NoPreferredResponse => write!(f, "no preferred response"),
            Error::InvalidHost(ref host) => write!(f, "invalid host {}", host),
            Error::UnknownHost(ref host) => write!(f, "unknown host {}", host),
            Error::IO(ref e) => write!(f, "{}", e),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let errmsg = format!("dns resolve error: {:?}", e);
        io::Error::new(io::ErrorKind::Other, errmsg)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IO(e)
    }
}

#[derive(Debug, Clone, Copy)]
enum HostnameStatus {
    First,
    Second,
}

// TODO: add last_activities to record last active time of hostname
pub struct Resolver {
    token: Token,
    prefer_ipv6: bool,
    hosts: HashMap<String, IpAddr>,
    cache: LruCache<String, IpAddr>,
    // query status
    hostname_status: HashMap<String, HostnameStatus>,
    token_to_hostname: HashMap<Token, String>,
    // multiple tokens query the same hostname
    hostname_to_tokens: HashMap<String, HashSet<Token>>,
    sock: UdpSocket,
    // DNS servers
    servers: Vec<SocketAddr>,
    qtypes: Vec<u16>,
    receive_buf: Option<Vec<u8>>,
}

impl Resolver {
    pub fn new(token: Token,
               server_list: Option<Vec<String>>,
               prefer_ipv6: bool)
               -> io::Result<Resolver> {
        let servers = Self::init_servers(server_list, prefer_ipv6)?;
        let (qtypes, addr) = if prefer_ipv6 {
            (vec![QType::AAAA, QType::A], "[::]:0")
        } else {
            (vec![QType::A, QType::AAAA], "0.0.0.0:0")
        };
        let addr = SocketAddr::from_str(addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let sock = UdpSocket::bind(&addr)?;
        let hosts = parse_hosts(prefer_ipv6);

        Ok(Resolver {
            token: token,
            prefer_ipv6: prefer_ipv6,
            servers: servers,
            hosts: hosts,
            cache: LruCache::new(CACHE_SIZE),
            hostname_status: HashMap::new(),
            token_to_hostname: HashMap::new(),
            hostname_to_tokens: HashMap::new(),
            sock: sock,
            qtypes: qtypes,
            receive_buf: Some(Vec::with_capacity(BUF_SIZE)),
        })
    }

    fn init_servers(server_list: Option<Vec<String>>,
                    prefer_ipv6: bool)
                    -> io::Result<Vec<SocketAddr>> {
        // pre-define DNS server list
        let server_list = match server_list {
            Some(servers) => servers,
            None => parse_resolv(prefer_ipv6),
        };
        let mut servers = vec![];
        for server in server_list {
            let ip_addr = pair2addr(&server, 53)?;
            servers.push(ip_addr);
        }

        Ok(servers)
    }

    pub fn get_token(&self) -> Token {
        self.token
    }

    fn send_request(&self, hostname: &str, qtype: u16) -> io::Result<()> {
        for server in &self.servers {
            let req = build_request(hostname, qtype).ok_or(Error::BuildRequestFailed)?;
            self.sock.send_to(&req, &server)?;
        }
        Ok(())
    }

    fn receive_data_into_buf(&mut self) -> io::Result<()> {
        let mut res = Ok(());
        let mut buf = self.receive_buf.take().unwrap();
        // get writable slice from vec
        let ptr = buf.as_mut_ptr();
        let cap = buf.capacity();
        let buf_slice = unsafe { &mut from_raw_parts_mut(ptr, cap) };
        unsafe {
            buf.set_len(0);
        }

        match self.sock.recv_from(buf_slice) {
            Ok(None) => {}
            Ok(Some((nread, _addr))) => unsafe {
                buf.set_len(nread);
            },
            Err(e) => res = Err(From::from(e)),
        }
        self.receive_buf = Some(buf);
        res
    }

    fn local_resolve(&mut self, hostname: &str) -> io::Result<Option<HostIpaddr>> {
        if hostname.is_empty() {
            Err(From::from(Error::EmptyHostName))
        } else if is_ip(hostname) {
            let ip_addr = str2ipaddr(hostname, self.prefer_ipv6).ok_or(
                Error::InvalidHost(hostname.to_string()))?;
            Ok(Some(HostIpaddr(hostname.to_string(), ip_addr)))
        } else if self.hosts.contains_key(hostname) {
            let ip_addr = self.hosts[hostname];
            Ok(Some(HostIpaddr(hostname.to_string(), ip_addr)))
        } else if self.cache.contains_key(hostname) {
            let ip_addr = self.cache.get_mut(hostname).unwrap().clone();
            Ok(Some(HostIpaddr(hostname.to_string(), ip_addr)))
        } else if !is_hostname(hostname) {
            Err(From::from(Error::InvalidHost(hostname.to_string())))
        } else {
            Ok(None)
        }
    }

    pub fn block_resolve(&mut self, hostname: &str) -> io::Result<Option<HostIpaddr>> {
        match self.local_resolve(hostname) {
            Ok(None) => {
                let mut sock_addr = None;
                for addr in (hostname, 0).to_socket_addrs()? {
                    if sock_addr.is_none() {
                        sock_addr = Some(addr);
                    }

                    if let SocketAddr::V6(_) = addr {
                        if self.prefer_ipv6 {
                            sock_addr = Some(addr);
                            break;
                        }
                    } else {
                        if !self.prefer_ipv6 {
                            sock_addr = Some(addr);
                            break;
                        }
                    }
                }

                let host_ipaddr = sock_addr.map(|addr| HostIpaddr(hostname.to_string(), addr.ip()));
                Ok(host_ipaddr)
            }
            res => res,
        }
    }

    pub fn resolve(&mut self, token: Token, hostname: &str) -> io::Result<Option<HostIpaddr>> {
        match self.local_resolve(hostname) {
            Ok(None) => {
                // if this is the first time that any caller query the hostname
                if !self.hostname_to_tokens.contains_key(hostname) {
                    self.hostname_status.insert(hostname.to_string(), HostnameStatus::First);
                    self.hostname_to_tokens.insert(hostname.to_string(), HashSet::new());
                }
                self.hostname_to_tokens.get_mut(hostname).unwrap().insert(token);
                self.token_to_hostname.insert(token, hostname.to_string());
                self.send_request(hostname, self.qtypes[0])?;
                Ok(None)
            }
            res => res,
        }
    }

    pub fn remove_token(&mut self, token: Token) -> Option<String> {
        let res = self.token_to_hostname.remove(&token);
        if let Some(ref hostname) = res {
            self.hostname_to_tokens.get_mut(hostname).map(|tokens| tokens.remove(&token));
            if self.hostname_to_tokens.get(hostname).unwrap().is_empty() {
                self.hostname_to_tokens.remove(hostname);
                self.hostname_status.remove(hostname);
            }
        }
        res
    }

    fn remove_hostname(&mut self, hostname: &str) -> HashSet<Token> {
        let mut tokens = HashSet::new();

        if let Some(related) = self.hostname_to_tokens.remove(hostname) {
            for token in related {
                self.token_to_hostname.remove(&token);
                tokens.insert(token);
            }
        }

        tokens
    }

    pub fn handle_events(&mut self, poll: &Poll, events: Ready) -> Result<ResolveResult, Error> {
        if events.is_error() {
            let e = self.sock
                .take_error()?
                .or(Some(io::Error::new(io::ErrorKind::Other, "event error")))
                .unwrap();
            let _ = poll.deregister(&self.sock);
            self.register(poll)?;

            self.hostname_status.clear();
            self.token_to_hostname.clear();
            self.hostname_to_tokens.clear();

            Err(Error::IO(e))
        } else {
            self.receive_data_into_buf()?;
            self.reregister(poll)?;
            let host_ipaddr = self.handle_recevied()?;
            let tokens = self.remove_hostname(&host_ipaddr.0);
            Ok(ResolveResult::new(tokens, host_ipaddr))
        }
    }

    fn handle_recevied(&mut self) -> Result<HostIpaddr, Error> {
        let receive_buf = self.receive_buf.take().unwrap();
        if receive_buf.is_empty() {
            self.receive_buf = Some(receive_buf);
            return Err(Error::BufferEmpty);
        }

        let res = if let Some(response) = parse_response(&receive_buf) {
            let hostname = response.hostname;
            let status = self.hostname_status.remove(&hostname);
            let mut ip = None;
            for answer in &response.answers {
                if (answer.1 == QType::A || answer.1 == QType::AAAA) && answer.2 == QClass::IN {
                    ip = str2ipaddr(&answer.0, self.prefer_ipv6);
                    break;
                }
            }

            if let Some(ip) = ip {
                self.cache.insert(hostname.clone(), ip);
                Ok(HostIpaddr(hostname, ip))
            } else {
                match status {
                    Some(HostnameStatus::First) => {
                        self.send_request(&hostname, self.qtypes[1])?;
                        self.hostname_status.insert(hostname, HostnameStatus::Second);
                        Err(Error::TryAgain)
                    }
                    Some(HostnameStatus::Second) => {
                        for question in response.questions {
                            if question.1 == self.qtypes[1] {
                                return Err(Error::UnknownHost(hostname));
                            }
                        }
                        Err(Error::NoPreferredResponse)
                    }
                    _ => Err(Error::UnknownHost(hostname)),
                }
            }
        } else {
            Err(Error::InvalidResponse)
        };

        self.receive_buf = Some(receive_buf);
        res
    }

    fn do_register(&mut self, poll: &Poll, is_reregister: bool) -> io::Result<()> {
        let events = Ready::readable();
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        if is_reregister {
            poll.reregister(&self.sock, self.token, events, pollopts)
                .map_err(From::from)
        } else {
            poll.register(&self.sock, self.token, events, pollopts).map_err(From::from)
        }
    }

    pub fn register(&mut self, poll: &Poll) -> io::Result<()> {
        self.do_register(poll, false)
    }

    fn reregister(&mut self, poll: &Poll) -> io::Result<()> {
        self.do_register(poll, true)
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;
    use std::time::Duration;
    use std::collections::HashMap;
    use mio::*;
    use super::*;

    const TIMEOUT: u64 = 5;
    const RESOLVER_TOKEN: Token = Token(0);
    const IPV4_TESTS: [(&'static str, &'static str); 3] = [("8.8.8.8", "8.8.8.8"),
                                                           ("localhost", "127.0.0.1"),
                                                           ("localhost.loggerhead.me",
                                                            "127.0.0.1")];

    const IPV6_TESTS: [(&'static str, &'static str); 3] = [("2001:4860:4860::8888",
                                                            "2001:4860:4860::8888"),
                                                           ("localhost", "::1"),
                                                           ("localhost.loggerhead.me", "::1")];

    fn init_resolver(prefer_ipv6: bool) -> (Resolver, HashMap<&'static str, IpAddr>) {
        let resolver = Resolver::new(RESOLVER_TOKEN, None, prefer_ipv6).unwrap();
        let tmp = if prefer_ipv6 { IPV6_TESTS } else { IPV4_TESTS };
        let mut tests = HashMap::new();
        for &(hostname, ip) in &tmp {
            let ip = super::super::network::str2ipaddr(ip, prefer_ipv6);
            assert!(ip.is_some());
            tests.insert(hostname, ip.unwrap());
        }

        (resolver, tests)
    }

    fn test_block_resolve(prefer_ipv6: bool) {
        let (mut resolver, tests) = init_resolver(prefer_ipv6);

        for (hostname, ip_addr) in tests {
            match resolver.block_resolve(hostname) {
                Ok(r) => {
                    assert!(r.is_some());
                    assert_eq!(r.unwrap(), super::HostIpaddr(hostname.to_string(), ip_addr));
                }
                Err(e) => {
                    println!("block_resolve failed: {:?}", e);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn ipv4_block_resolve() {
        test_block_resolve(false);
    }

    // TODO: test ipv6 related tests
    // this test may failed if your computer is not a prefer_ipv6 host
    #[test]
    #[ignore]
    fn ipv6_block_resolve() {
        test_block_resolve(true);
    }

    fn test_mio_loop(prefer_ipv6: bool) {
        let (mut resolver, tests) = init_resolver(prefer_ipv6);

        let poll = Poll::new().unwrap();
        resolver.register(&poll).unwrap();
        let mut events = Events::with_capacity(1024);

        let mut i = 0;
        for (hostname, &ip_addr) in &tests {
            i += 1;
            match resolver.resolve(Token(i), hostname) {
                Ok(Some(host_ipaddr)) => {
                    assert_eq!(HostIpaddr(hostname.to_string(), ip_addr), host_ipaddr);
                    continue;
                }
                _ => {}
            }

            match poll.poll(&mut events, Some(Duration::new(TIMEOUT, 0))) {
                Ok(_) => {
                    for event in events.iter() {
                        match event.token() {
                            RESOLVER_TOKEN => {
                                let r = resolver.handle_events(&poll, event.kind());
                                assert!(r.is_ok());
                                let r = r.unwrap();

                                assert!(r.tokens.contains(&Token(i)));
                                assert_eq!(r.result, HostIpaddr(hostname.to_string(), ip_addr));
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                _ => assert!(false),
            }
        }
    }

    #[test]
    fn mio_loop_ipv4() {
        test_mio_loop(false);
    }

    #[test]
    #[ignore]
    fn mio_loop_ipv6() {
        test_mio_loop(true);
    }
}
