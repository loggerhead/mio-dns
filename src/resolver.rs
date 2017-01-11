use std::io;
use std::fmt;
use std::str::FromStr;
use std::convert::From;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs, SocketAddr};

use lru_cache::LruCache;
use mio::{Token, Ready, Poll, PollOpt};
use mio::udp::UdpSocket;

use network::*;
use parser::*;
use super::{QType, QClass};

const CACHE_SIZE: usize = 1024;
const BUF_SIZE: usize = 1024;

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
    dns_servers: Vec<SocketAddr>,
    qtypes: Vec<u16>,
    received: [u8; BUF_SIZE],
}

impl Resolver {
    pub fn new(token: Token,
               server_list: Option<Vec<String>>,
               prefer_ipv6: bool)
               -> io::Result<Resolver> {
        let dns_servers = Self::init_dns_servers(server_list, prefer_ipv6)?;
        if dns_servers.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "no dns servers available"));
        }
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
            dns_servers: dns_servers,
            hosts: hosts,
            cache: LruCache::new(CACHE_SIZE),
            hostname_status: HashMap::new(),
            token_to_hostname: HashMap::new(),
            hostname_to_tokens: HashMap::new(),
            sock: sock,
            qtypes: qtypes,
            received: [0u8; BUF_SIZE],
        })
    }

    fn init_dns_servers(server_list: Option<Vec<String>>,
                        prefer_ipv6: bool)
                        -> io::Result<Vec<SocketAddr>> {
        // pre-define DNS server list
        let server_list = match server_list {
            Some(dns_servers) => dns_servers,
            None => parse_resolv(prefer_ipv6),
        };
        let mut dns_servers = vec![];
        for server in server_list {
            let ip_addr = pair2addr(&server, 53)?;
            dns_servers.push(ip_addr);
        }

        Ok(dns_servers)
    }

    pub fn get_token(&self) -> Token {
        self.token
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

    fn send_request(&self, hostname: &str, qtype: u16) -> io::Result<()> {
        for server in &self.dns_servers {
            let req = build_request(hostname, qtype).ok_or(Error::BuildRequestFailed)?;
            self.sock.send_to(&req, &server)?;
        }
        Ok(())
    }

    fn recv_into_buf(&mut self) -> io::Result<usize> {
        match self.sock.recv_from(&mut self.received) {
            Ok(None) => Ok(0),
            Ok(Some((nread, addr))) => {
                if self.dns_servers.contains(&addr) || cfg!(feature = "allow_unknow_server") {
                    Ok(nread)
                } else {
                    Err(From::from(Error::UnknownDns(addr)))
                }
            }
            Err(e) => Err(e),
        }
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

                Ok(sock_addr.map(|addr| HostIpaddr(hostname.to_string(), addr.ip())))
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

    // if no tokens in `ResolveResult`, it means there exists
    // multiple query of the same hostname, and the related tokens
    // are removed in the first response
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
            let res = match self.recv_into_buf() {
                Ok(0) => Err(Error::BufferEmpty),
                Ok(n) => {
                    let host_ipaddr = self.handle_recevied(n)?;
                    let tokens = self.remove_hostname(&host_ipaddr.0);
                    Ok(ResolveResult::new(tokens, host_ipaddr))
                }
                Err(e) => Err(From::from(e)),
            };
            self.reregister(poll)?;
            res
        }
    }

    fn handle_recevied(&mut self, nread: usize) -> Result<HostIpaddr, Error> {
        let data = &self.received[..nread];
        if let Some(response) = parse_response(data) {
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
                        Err(Error::TrySecond)
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
        }
    }

    fn do_register(&mut self, poll: &Poll, is_reregister: bool) -> io::Result<()> {
        let events = Ready::readable();
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        if is_reregister {
                poll.reregister(&self.sock, self.token, events, pollopts)
            } else {
                poll.register(&self.sock, self.token, events, pollopts)
            }
            .map_err(From::from)
    }

    pub fn register(&mut self, poll: &Poll) -> io::Result<()> {
        self.do_register(poll, false)
    }

    fn reregister(&mut self, poll: &Poll) -> io::Result<()> {
        self.do_register(poll, true)
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct HostIpaddr(pub String, pub IpAddr);

impl fmt::Display for HostIpaddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {})", self.0, self.1)
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ResolveResult {
    pub tokens: HashSet<Token>,
    pub result: HostIpaddr,
}

impl fmt::Display for ResolveResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} => {}", self.tokens, self.result)
    }
}

impl ResolveResult {
    fn new(tokens: HashSet<Token>, result: HostIpaddr) -> ResolveResult {
        ResolveResult {
            tokens: tokens,
            result: result,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum HostnameStatus {
    First,
    Second,
}

pub enum Error {
    TrySecond,
    Timeout,
    BufferEmpty,
    EmptyHostName,
    InvalidResponse,
    BuildRequestFailed,
    NoPreferredResponse,
    InvalidHost(String),
    UnknownHost(String),
    UnknownDns(SocketAddr),
    IO(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::TrySecond => write!(f, "try another QTYPE"),
            Error::Timeout => write!(f, "timeout"),
            Error::BufferEmpty => write!(f, "no buffered data available"),
            Error::EmptyHostName => write!(f, "empty hostname"),
            Error::InvalidResponse => write!(f, "invalid response"),
            Error::BuildRequestFailed => write!(f, "build dns request failed"),
            Error::NoPreferredResponse => write!(f, "no preferred response"),
            Error::InvalidHost(ref host) => write!(f, "invalid host {}", host),
            Error::UnknownHost(ref host) => write!(f, "unknown host {}", host),
            Error::UnknownDns(ref server) => write!(f, "unknown dns server {}", server),
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

#[cfg(test)]
mod test {
    use std::io;
    use std::collections::HashSet;
    use mio::*;
    use super::*;

    const RESOLVER_TOKEN: Token = Token(0);
    const TESTS: &'static [&'static str] = &["8.8.8.8",
                                             "localhost",
                                             "localhost.loggerhead.me",
                                             "2001:4860:4860::8888",
                                             "localhost.loggerhead.me"];


    fn test_block_resolve(prefer_ipv6: bool) {
        let mut resolver = Resolver::new(RESOLVER_TOKEN, None, prefer_ipv6).unwrap();

        for hostname in TESTS {
            match resolver.block_resolve(hostname) {
                Ok(Some(host_ipaddr)) => {
                    println!("{}", host_ipaddr);
                }
                Ok(None) => assert!(false),
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

    #[test]
    fn ipv6_block_resolve() {
        test_block_resolve(true);
    }

    fn test_mio_loop(prefer_ipv6: bool) -> io::Result<()> {
        let mut resolver = Resolver::new(RESOLVER_TOKEN, None, prefer_ipv6).unwrap();
        let poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);
        let mut hostnames: HashSet<&str> = HashSet::new();
        resolver.register(&poll).unwrap();

        let mut i = RESOLVER_TOKEN.0 + 1;
        for hostname in TESTS {
            let token = Token(i);
            i += 1;

            if let Ok(Some(host_ipaddr)) = resolver.resolve(token, hostname) {
                println!("{{{:?}}} => {}", token, host_ipaddr);
            } else {
                hostnames.insert(hostname);
            }
        }

        println!("wait to resolve:\n{:?}", hostnames);

        while !hostnames.is_empty() {
            if let 0 = poll.poll(&mut events, None)? {
                continue;
            }

            for event in events.iter() {
                match event.token() {
                    RESOLVER_TOKEN => {
                        match resolver.handle_events(&poll, event.kind()) {
                            Ok(r) => {
                                hostnames.remove(&r.result.0 as &str);
                                println!("{}", r);
                            }
                            Err(e) => {
                                println!("resolve error: {}", e);
                                assert!(false);
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }

            i -= 1;
        }

        Ok(())
    }

    #[test]
    fn mio_loop_ipv4() {
        assert!(test_mio_loop(false).is_ok());
    }

    // TODO: test ipv6 related tests
    // this test may failed if your computer is not a prefer_ipv6 host
    #[test]
    #[ignore]
    fn mio_loop_ipv6() {
        assert!(test_mio_loop(true).is_ok());
    }
}
