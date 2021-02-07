//! Checks SSL certificate expiration.
//!
//! This crate will try to connect a remote server and check SSL certificate expiration.
//!
//! Basic usage example:
//!
//! ```rust
//! use ssl_expiration2::SslExpiration;
//!
//! let expiration = SslExpiration::from_domain_name("google.com").unwrap();
//! if expiration.is_expired() {
//!     // do something if SSL certificate expired
//! }
//! ```
//!
//! Check days before expiration example:
//!
//! ```rust
//! use ssl_expiration2::SslExpiration;
//!
//! let expiration =
//!     SslExpiration::from_domain_name("google.com").expect("Domain validation has to work");
//! if expiration.days() < 14 {
//!     // SSL certificate will expire in less than 2 weeks, run notification…
//! }
//! ```


#[macro_use]
extern crate error_chain;

use error::{Error, ErrorKind, Result};
use error_chain::State;
use openssl::{
    asn1::*,
    ssl::{Ssl, SslContext, SslMethod, SslVerifyMode},
};
use openssl_sys::ASN1_TIME;
use std::{
    net::{TcpStream, ToSocketAddrs},
    os::raw::c_int,
    time::Duration,
};


extern "C" {
    fn ASN1_TIME_diff(
        pday: *mut c_int,
        psec: *mut c_int,
        from: *const ASN1_TIME,
        to: *const ASN1_TIME,
    );
}


pub struct SslExpiration(c_int);

impl SslExpiration {
    /// Creates new SslExpiration from domain name.
    ///
    /// This function will use HTTPS port (443) to check SSL certificate with 30 seconds timeout.
    pub fn from_domain_name(domain: &str) -> Result<SslExpiration> {
        SslExpiration::from_addr(format!("{}:443", domain), domain, 30) // seconds
    }

    /// This function will use HTTPS port (443) to check SSL certificate with custom timeout.
    pub fn from_domain_name_with_timeout(domain: &str, timeout: u64) -> Result<SslExpiration> {
        SslExpiration::from_addr(format!("{}:443", domain), domain, timeout)
    }

    /// Creates new SslExpiration from SocketAddr.
    pub fn from_addr<A: ToSocketAddrs>(
        addr: A,
        domain: &str,
        timeout: u64,
    ) -> Result<SslExpiration> {
        let context = {
            let mut context = SslContext::builder(SslMethod::tls())?;
            context.set_verify(SslVerifyMode::empty());
            context.build()
        };
        let mut connector = Ssl::new(&context)?;
        connector.set_hostname(domain)?;
        match addr.to_socket_addrs()?.next() {
            Some(first_address) => {
                let stream =
                    TcpStream::connect_timeout(&first_address, Duration::from_secs(timeout))?;
                stream.set_write_timeout(Some(Duration::from_secs(timeout)))?;
                stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;

                let stream = connector
                    .connect(stream)
                    .map_err(|e| ErrorKind::HandshakeError(e.to_string()))?;
                let cert = stream
                    .ssl()
                    .peer_certificate()
                    .ok_or("Certificate not found")?;

                let now = Asn1Time::days_from_now(0)?;

                let (mut pday, mut psec) = (0, 0);
                let ptr_pday: *mut c_int = &mut pday;
                let ptr_psec: *mut c_int = &mut psec;
                let now_ptr = &now as *const _ as *const _;
                let after_ptr = &cert.not_after() as *const _ as *const _;
                unsafe {
                    ASN1_TIME_diff(ptr_pday, ptr_psec, *now_ptr, *after_ptr);
                }

                Ok(SslExpiration(pday * 24 * 60 * 60 + psec))
            }
            None => {
                Err(Error(
                    ErrorKind::HandshakeError(format!(
                        "Couldn't resolve any address from domain: {}",
                        &domain
                    )),
                    State::default(),
                ))
            }
        }
    }

    /// How many seconds until SSL certificate expires.
    ///
    /// This function will return minus if SSL certificate is already expired.
    pub fn secs(&self) -> i32 {
        self.0
    }

    /// How many days until SSL certificate expires
    ///
    /// This function will return minus if SSL certificate is already expired.
    pub fn days(&self) -> i32 {
        self.0 / 60 / 60 / 24
    }

    /// Returns true if SSL certificate is expired
    pub fn is_expired(&self) -> bool {
        self.0 < 0
    }
}

pub mod error {
    use std::io;

    error_chain! {
        foreign_links {
            OpenSslErrorStack(openssl::error::ErrorStack);
            IoError(io::Error);
        }
        errors {
            HandshakeError(e: String) {
                display("HandshakeError: {}", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_ssl_not_expired() {
        assert!(
            !SslExpiration::from_domain_name("google.com")
                .unwrap()
                .is_expired()
        );
        let days = SslExpiration::from_domain_name("google.com")
            .unwrap()
            .days();
        assert!(days > 14)
    }


    #[test]
    fn test_too_small_timeout_chain() {
        SslExpiration::from_domain_name_with_timeout("google.com", 0)
            .and_then(|_| Ok(assert!(false)))
            .unwrap_or_else(|_| assert!(true));
    }


    #[test]
    fn test_unresolvable_timeout_chain() {
        SslExpiration::from_domain_name_with_timeout("unresolvable.net", 3)
            .and_then(|_| Ok(assert!(false)))
            .map_err(|e| println!("Error: {:?}", e))
            .unwrap_or_else(|_| assert!(true));
    }


    #[test]
    fn test_sufficient_timeout_chain() {
        SslExpiration::from_domain_name_with_timeout("google.com", 30)
            .and_then(|_| Ok(assert!(true)))
            .unwrap_or_else(|_| assert!(false));
    }


    #[test]
    fn test_non_panicing_chain() {
        SslExpiration::from_domain_name("google.com")
            .and_then(|validity| Ok(assert!(validity.days() > 14)))
            .unwrap_or_else(|_| assert!(false));
    }


    #[test]
    fn test_ssl_expired() {
        assert!(
            SslExpiration::from_domain_name("expired.identrustssl.com")
                .unwrap()
                .is_expired()
        );
    }
}
