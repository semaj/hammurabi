use openssl::x509::X509;
use std::{env, fs};
use serde::Deserialize;
use docopt::Docopt;

use acclib;


const USAGE: &'static str = "
Verifies certificate at <path> for host <hostname> using policy for client <client>.
<client> should be chrome or firefox.
<path> should be an absolute path, because rustls has some silly behavior regarding paths.

Usage:
  single [options] <client> <path> <hostname> [--ocsp] [--staple]
  single (--version | -v)
  single (--help | -h)

Options:
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_client: String,
    arg_path: String,
    arg_hostname: String,
    flag_ocsp: bool,
    flag_staple: bool,
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let jobindex = env::var("JOBINDEX").unwrap_or("".to_string());
    let job_dir = format!("prolog/job{}", jobindex);


    let chain_raw = fs::read(&args.arg_path).unwrap();
    let mut chain = X509::stack_from_pem(&chain_raw).unwrap();
    let domain = &args.arg_hostname.to_lowercase();

    let facts = acclib::get_chain_facts(&mut chain, None, args.flag_ocsp, args.flag_staple).unwrap();
    acclib::write_job_files(&job_dir, domain, &facts).unwrap();
    match acclib::verify_chain(&job_dir, &args.arg_client) {
        Ok(_) => println!("OK"),
        Err(e) => println!("Error: {:?}", e),
    }
}


