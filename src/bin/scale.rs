use openssl::x509::X509;
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Write};

use docopt::Docopt;

const USAGE: &'static str = "
Verifies certificate at <path> for host <hostname>.
<path> should be an absolute path, because rustls has some silly behavior regarding paths.

Usage:
  localcheck [options] <mappingfile> <intpath> <outputfile>
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
    arg_mappingfile: String,
    arg_intpath: String,
    //arg_workingPath: String, (thread-safety)
    arg_outputfile: String,
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
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_path(&args.arg_mappingfile).unwrap();
    let mut out_file = File::create(&args.arg_outputfile).unwrap();
    rdr.records().for_each(|f| {
        let record = f.unwrap();
        let row: Row = record.deserialize(None).unwrap();
        let chain_raw = form_chain(&row.certificate_bytes, &args.arg_intpath, &row.ints);
        let mut chain = X509::stack_from_pem(&chain_raw.as_bytes()).unwrap();
        let domain = row.domain.as_str();
        let result = acclib::verify_prolog(&mut chain, &domain, None, false);
        let result_str = match result {
            Ok(_) => "OK".to_string(),
            Err(e) => format!("{:?}", e),
        };
        out_file.write_all(
            format!("{},{},{}\n",
                    row.sha256,
                    domain,
                    result_str).as_bytes()
            ).unwrap();

    });

}


