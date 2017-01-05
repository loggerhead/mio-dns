extern crate mio;
extern crate mio_dns;

use std::time::Duration;

use mio::*;
use mio_dns::{Resolver, HostIpaddr};

const TIMEOUT: u64 = 5;
const PREFER_IPV6: bool = false;
const RESOLVER_TOKEN: Token = Token(0);
const TESTS: &'static [&'static str] = &["8.8.8.8",
                                         "localhost",
                                         "localhost.loggerhead.me",
                                         "www.baidu.com",
                                         "localhost.loggerhead.me"];

fn main() {
    let poll_timeout = Duration::new(TIMEOUT, 0);
    let mut resolver = Resolver::new(RESOLVER_TOKEN, None, PREFER_IPV6).unwrap();

    let poll = Poll::new().unwrap();
    resolver.register(&poll).unwrap();
    let mut events = Events::with_capacity(1024);

    let mut i = 0;
    for hostname in TESTS {
        i += 1;
        match resolver.resolve(Token(i), hostname) {
            Ok(None) => {
                match poll.poll(&mut events, Some(poll_timeout)) {
                    Ok(_) => {
                        for event in events.iter() {
                            match event.token() {
                                RESOLVER_TOKEN => {
                                    match resolver.handle_events(&poll, event.kind()) {
                                        Ok(r) => {
                                            println!("{:?}", r.tokens);
                                            print_hostipaddr(&r.result);
                                            println!();
                                        }
                                        Err(e) => println!("ERROR: {}", e),
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    Err(e) => println!("ERROR: {}", e),
                }
            }
            Ok(Some(host_ipaddr)) => {
                print_hostipaddr(&host_ipaddr);
            }
            Err(e) => println!("ERROR: {}", e),
        }
    }
}

fn print_hostipaddr(host_ipaddr: &HostIpaddr) {
    println!("{} => {}", host_ipaddr.0, host_ipaddr.1);
}
