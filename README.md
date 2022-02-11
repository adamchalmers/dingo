# Dingo

Domain information gatherer, obviously.

## Installation

Run `cargo build --release` and copy the binary from `target/release/dingo` to somewhere.

## Examples
```sh
$ dingo --record-type A seriouseats.com

# Output
Questions:
A: seriouseats.com.
Answers:
151.101.2.137 (TTL 142)
151.101.194.137 (TTL 142)
151.101.130.137 (TTL 142)
151.101.66.137 (TTL 142)
```

## Usage
```
dingo [OPTIONS] --record-type TYPE NAME

FLAGS:
  -h, --help                Prints help information
OPTIONS:
  -t, --record-type TYPE    Choose the DNS record type (currently only supports A, CNAME)
  -r, --resolver IP         Which DNS resolver to query (default is 1.1.1.1:53)
ARGS:
  NAME A domain name to look up. Remember, these must be ASCII.
```
