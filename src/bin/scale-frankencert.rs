use openssl::x509::X509;
use openssl::nid::Nid;
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use rayon;
use rayon::prelude::*;
use std::sync::Arc;
//use ipaddress::IPAddress;

use docopt::Docopt;

const USAGE: &'static str = "
Verifies certificate at <path> for host <hostname> using policy for client <client>.
<client> should be chrome or firefox.
<path> should be an absolute path, because rustls has some silly behavior regarding paths.

Usage:
  scale [options] <client> <chainpath> <outpath> --start=<start> --end=<end>
  scale (--version | -v)
  scale (--help | -h)

Options:
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_client: String,
    arg_chainpath: String,
    arg_outpath: String,
    flag_start: usize,
    flag_end: usize,
}

#[derive(Debug, Deserialize)]
struct Row {
    certificate_bytes: String,
    sha256: String,
    domain: String,
    ints: String, // Comma separated, surrounded by quotes
}

fn read_disk_certificate(filename: &str) -> std::io::Result<String> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    let arc = Arc::new(args);
    (arc.flag_start..=arc.flag_end).into_par_iter().for_each(|n| {
        let arc = Arc::clone(&arc);
        let index = rayon::current_thread_index().unwrap_or(1);
        let mut out_file = File::create(format!("{}/{}-out-{}.csv", &arc.arg_outpath, &arc.arg_client,  n)).unwrap();
        let chain_raw = read_disk_certificate(&format!("{}/frankencert-{}.pem", &arc.arg_chainpath, n)).unwrap();
        let mut chain = X509::stack_from_pem(&chain_raw.as_bytes()).unwrap();
        let name = match chain[0].subject_alt_names() {
            Some(san) => {
                match san[0].dnsname() {
                    Some(s) => s.to_string(),
                    None => "nope".to_string(),
                }
            },
            None => {
                //"test"
                match chain[0].subject_name().entries_by_nid(Nid::COMMONNAME).next() {
                    Some(x) => {
                        println!("{:?}", x);
                        match x.data().as_utf8() {
                            Ok(y) => format!("{}", y),
                            Err(_) => "nope".to_string(),
                        }
                    },
                    None => "nope".to_string(),
                }
            }
        }.replace("*", "www");
        //match IPAddress::parse(name) {
            //Ok(_) => {
                //println!("Skipping IP {}", name);
                //write!(out_file, "{},{},SKIPPED\n", n, name).unwrap();
                //return
            //},
            //_ => {}
        //}
        let domain = &name.to_lowercase();
        let job_dir = format!("prolog/job/{}-{}-{}", &arc.arg_client, n, index);

        match acclib::get_chain_facts(&mut chain, None, false, false) {
            Ok(facts) => {
                acclib::write_job_files(&job_dir, domain, &facts).unwrap();
                let result = acclib::verify_chain(&job_dir, &arc.arg_client);
                let result_str = match result {
                    Ok(_) => "OK".to_string(),
                    Err(e) =>{
                        format!("{:?}", e)
                    }
                };
                println!("{},{},{},{}", n, result_str, name, job_dir);
                write!(out_file, "{},{},{}\n", n, domain, result_str).unwrap();
            }
            Err(e) => {
                println!("{},{:?},{},{}", n, e, name, job_dir);
                write!(out_file, "{},{},{:?}\n", n, domain, e).unwrap();
            }
        }
        //pool.spawn(move || {
        //});
    });
}


