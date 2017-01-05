#[macro_use]
extern crate try_opt;
extern crate lru_cache;
extern crate byteorder;
extern crate rand;
extern crate mio;

#[allow(dead_code, non_snake_case)]
mod QType {
    pub const A: u16 = 1;
    pub const AAAA: u16 = 28;
    pub const CNAME: u16 = 5;
    pub const NS: u16 = 2;
    pub const ANY: u16 = 255;
}

#[allow(dead_code, non_snake_case)]
mod QClass {
    pub const IN: u16 = 1;
}

#[macro_use]
pub mod network;
mod parser;
pub mod resolver;

pub use resolver::{Error, Resolver, ResolveResult, HostIpaddr};
