use openssl::x509::X509;
use std::fs;
use serde::Deserialize;

use acclib;

use docopt::Docopt;

const USAGE: &'static str = "
Verifies certificate at <path> for host <hostname>.
<path> should be an absolute path, because rustls has some silly behavior regarding paths.

Usage:
  localcheck [options] <path> <hostname>
  localcheck (--version | -v)
  localcheck (--help | -h)

Options:
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_path: String,
    arg_hostname: String,
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    let chain_raw = fs::read(&args.arg_path).unwrap();
    let mut chain = X509::stack_from_pem(&chain_raw).unwrap();
    match acclib::verify_prolog(&mut chain, &args.arg_hostname, None, false) {
        Ok(_) => println!("OK"),
        Err(e) => println!("Error: {:?}", e),
    }
}


