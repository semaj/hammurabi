use openssl::x509::X509;
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use rayon;
use std::thread;
use rayon::prelude::*;
use std::sync::Arc;

use docopt::Docopt;

const USAGE: &'static str = "
Verifies certificate at <path> for host <hostname> using policy for client <client>.
<client> should be chrome or firefox.
<path> should be an absolute path, because rustls has some silly behavior regarding paths.

Usage:
  localcheck [options] <client> <mappingpath> <intpath> <outpath> --start=<start> --end=<end> [--ocsp] 
  localcheck (--version | -v)
  localcheck (--help | -h)

Options:
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";
const HEADER: &'static str = "-----BEGIN CERTIFICATE-----";
const FOOTER: &'static str = "-----END CERTIFICATE-----";

#[derive(Debug, Deserialize)]
struct Args {
    arg_client: String,
    arg_mappingpath: String,
    arg_intpath: String,
    arg_outpath: String,
    flag_start: usize,
    flag_end: usize,
    flag_ocsp: bool,
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

fn form_chain(leaf: &String, intpath: &str, ints: &String) -> String {
    // Wrap leaf in Certificate header/Footer
    let formatted_leaf = format!("{}\r\n{}\r\n{}\r\n", HEADER, leaf, FOOTER);
    let split_ints: Vec<&str> = ints.split(",").collect();
    let p = split_ints.iter().map(|f| {
        let filename = format!("{}/{}{}", intpath, f, ".pem");
        let int = read_disk_certificate(&filename).unwrap();
        format!("{}", int)
    }).collect::<String>();
    let formatted_chain = format!("{}{}", formatted_leaf, p);
    format!("{}", formatted_chain)
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    //let pool = rayon::ThreadPoolBuilder::new().num_threads(args.arg_threads.unwrap_or(8)).build().unwrap();
    let arc = Arc::new(args);
    (arc.flag_start..=arc.flag_end).into_par_iter().for_each(|n| {
        let arc = Arc::clone(&arc);
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_path(format!("{}/cert-list-part-{}.txt", &arc.arg_mappingpath, n)).unwrap();
        let mut out_file = File::create(format!("{}/cert-list-part-{}.csv", &arc.arg_outpath, n)).unwrap();
        rdr.records().for_each(|f| {
                let index = rayon::current_thread_index().unwrap();
                //let index = thread::current().id();
                let record = f.unwrap();
                let row: Row = record.deserialize(None).unwrap();
                let chain_raw = form_chain(&row.certificate_bytes, &arc.arg_intpath, &row.ints);
                let mut chain = X509::stack_from_pem(&chain_raw.as_bytes()).unwrap();
                let domain = row.domain.as_str();
                let job_dir = format!("prolog/job/{}", index);

                let facts = acclib::get_chain_facts(&mut chain, None, arc.flag_ocsp, false).unwrap();
                acclib::write_job_files(&job_dir, domain, &facts).unwrap();
                let result = acclib::verify_chain(&job_dir, &arc.arg_client);
                let result_str = match result {
                    Ok(_) => "OK".to_string(),
                    Err(e) => format!("{:?}", e),
                };
                println!("{}", result_str);
                write!(out_file, "{},{},{}\n", row.sha256, domain, result_str).unwrap();
            //pool.spawn(move || {
            //});
        });
    });
}


