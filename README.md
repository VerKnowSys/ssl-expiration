# ssl-expiration2

Checks SSL certificate expiration.

## Usage

```rust
use ssl_expiration2::SslExpiration;

let expiration = SslExpiration::from_domain_name("google.com").unwrap();
if expiration.is_expired() {
    // do something if SSL certificate expired
}
```

```rust
use ssl_expiration2::SslExpiration;

let expiration =
    SslExpiration::from_domain_name("google.com").expect("Domain validation has to work");
if expiration.days() < 14 {
    // SSL certificate will expire in less than 2 weeks, run notification…
}

```
