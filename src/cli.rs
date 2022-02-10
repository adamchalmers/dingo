use crate::dns_types::RecordType;

const HELP: &str = "\
dingo -- domain information gatherer, obviously
USAGE:
  dingo --record-type TYPE NAME
FLAGS:
  -h, --help                    Prints help information
OPTIONS:
  -t, --record-type TYPE       Choose the DNS record type (A, CNAME, AAAA etc)
ARGS:
  NAME A domain name to look up. Remember, these must be ASCII.
";

/// Values derived from the CLI arguments.
#[derive(Debug)]
pub struct AppArgs {
    pub record_type: RecordType,
    pub name: String,
}

impl AppArgs {
    pub fn parse() -> Result<Self, pico_args::Error> {
        let mut pargs = pico_args::Arguments::from_env();

        // Help has a higher priority and should be handled separately.
        if pargs.contains(["-h", "--help"]) {
            print!("{}", HELP);
            std::process::exit(0);
        }

        let record_type = match pargs
            .opt_value_from_str("--record-type")?
            .xor(pargs.opt_value_from_str("-t")?)
        {
            Some(rt) => rt,
            None => {
                eprintln!("You must supply exactly one of either -t or --record-type");
                std::process::exit(1);
            }
        };
        let mut name: String = pargs.free_from_str()?;
        if !name.ends_with('.') {
            name.push('.');
        }
        let args = AppArgs { record_type, name };

        let remaining = pargs.finish();
        if !remaining.is_empty() {
            eprintln!("Warning: unused arguments left: {:?}.", remaining);
        }

        Ok(args)
    }
}
