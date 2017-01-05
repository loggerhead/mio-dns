extern crate mio;
extern crate mio_dns;

use std::time::Duration;
use std::io::Result;

use mio::*;
use mio_dns::{Resolver, HostIpaddr};

const TIMEOUT: u64 = 5;
const PREFER_IPV6: bool = false;
const RESOLVER_TOKEN: Token = Token(0);
const TESTS: &'static [&'static str] = &["8.8.8.8",
                                         "localhost",
                                         "localhost.loggerhead.me",
                                         "www.baidu.com",
                                         // test cache
                                         "localhost.loggerhead.me"];

fn main() {
    let poll_timeout = Duration::new(TIMEOUT, 0);
    let mut resolver = Resolver::new(RESOLVER_TOKEN, None, PREFER_IPV6).unwrap();

    let poll = Poll::new().unwrap();
    resolver.register(&poll).unwrap();
    let mut events = Events::with_capacity(1024);

    for hostname in TESTS {
        match query(hostname, &mut resolver, &poll, &mut events, poll_timeout) {
            Err(e) => println!("ERROR: {}", e),
            _ => {}
        }
    }
}

fn query(hostname: &'static str,
         resolver: &mut Resolver,
         poll: &Poll,
         events: &mut Events,
         timeout: Duration) -> Result<()> {
    #[allow(non_upper_case_globals)]
    static mut i: usize = 0;
    let token = unsafe {
        i += 1;
        Token(i)
    };

    println!("<--------- {}", hostname);
    let r = resolver.resolve(token, hostname)?;
    match r {
        None => {
            if poll.poll(events, Some(timeout))? == 0 {
                println!("ERROR: no events get of {}", hostname);
            }
            for event in events.iter() {
                match event.token() {
                    RESOLVER_TOKEN => {
                        let r = resolver.handle_events(&poll, event.kind())?;
                        print_hostipaddr(&r.result);
                        println!("    => {:?}", r.tokens);
                    }
                    _ => unreachable!(),
                }
            }
        }
        Some(host_ipaddr) => {
            print_hostipaddr(&host_ipaddr);
        }
    }
    Ok(())
}

fn print_hostipaddr(host_ipaddr: &HostIpaddr) {
    println!("({}, {})", host_ipaddr.0, host_ipaddr.1);
}
