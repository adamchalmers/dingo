# Dingo

Domain INformation Gatherer, Obviously.

## Installation

1. Install cargo, see [instructions on the Rust website](https://doc.rust-lang.org/cargo/getting-started/installation.html)
2. Run ./install.sh (it just does cargo build and copies the program to `/usr/local/bin/dingo`)

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
  -t, --record-type TYPE    Choose the DNS record type (does not support anywhere near all the record types)
  -r, --resolver IP         Which DNS resolver to query (default is 1.1.1.1:53)
ARGS:
  NAME A domain name to look up. Remember, these must be ASCII.
```
