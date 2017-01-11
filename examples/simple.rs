extern crate mio;
extern crate mio_dns;

use std::collections::HashSet;

use mio::*;
use mio_dns::Resolver;

const PREFER_IPV6: bool = false;
const RESOLVER_TOKEN: Token = Token(0);
const TESTS: &'static [&'static str] = &[
    "8.8.8.8",
    "localhost",
    "localhost.loggerhead.me",
    "2001:4860:4860::8888",
    // test cache
    "www.baidu.com",
    "localhost.loggerhead.me",
    "www.baidu.com",
];

fn main() {
    let mut resolver = Resolver::new(RESOLVER_TOKEN, None, PREFER_IPV6).unwrap();

    let poll = Poll::new().unwrap();
    resolver.register(&poll).unwrap();
    let mut events = Events::with_capacity(1024);
    let mut hostnames: HashSet<&str> = HashSet::new();

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

    while !hostnames.is_empty() {
        match poll.poll(&mut events, None) {
            Ok(0) => continue,
            Err(e) => {
                println!("poll error: {}", e);
                continue;
            }
            _ => {}
        }

        for event in events.iter() {
            match event.token() {
                RESOLVER_TOKEN => {
                    match resolver.handle_events(&poll, event.kind()) {
                        Ok(r) => {
                            hostnames.remove(&r.result.0 as &str);
                            println!("{}", r);
                        }
                        Err(e) => println!("resolve error: {}", e),
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}
