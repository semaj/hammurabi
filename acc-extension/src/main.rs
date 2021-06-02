extern crate openssl;

use openssl::x509::{X509, X509Name, X509Extension};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
//use openssl::nid::Nid;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use openssl::asn1::Asn1Time;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    //println!("{} {}", &args[0], args.len());
    if args.len() < 3 {
        println!("usage: acc-extension <acc-content> <output>");
        process::exit(1);
    }
    
    // read ACC content
    let acc_path = &args[1]; // path to acc content file
    let mut acc_file = File::open(&acc_path).unwrap();
    let mut acc_content = String::new();
    acc_file.read_to_string(&mut acc_content).unwrap();

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509Name::builder().unwrap();

    //name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com").unwrap();
    name.append_entry_by_text("C", "US").unwrap();
    //name.append_entry_by_text("ST", "CA").unwrap();
    name.append_entry_by_text("O", "Some organization").unwrap();
    name.append_entry_by_text("CN", "www.example.com").unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();


    let not_before: Asn1Time = Asn1Time::days_from_now(0).unwrap();
    let not_after: Asn1Time = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();


    // add ACC extension
    let mut value = String::from("critical,ASN1:UTF8String:");
    value.push_str(&acc_content);
    let acc_oid = String::from("1.2.3.4");
    let acc_ext: X509Extension = X509Extension::new(None, None,&acc_oid, &value
    )
        .unwrap();
    builder.append_extension(acc_ext).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let certificate: X509 = builder.build();

    let cert_pem: Vec<u8> = match certificate.to_pem() {
        Err(why) => panic!("couldn't serialize cert: {}", why),
        Ok(cert) => cert,
    };

    let path = Path::new(&args[2]);
    let display = path.display();

    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };
    match file.write_all(&cert_pem) {
        Err(why) => panic!("couldn't write to {}: {}", display, why),
        Ok(_) => println!("successfully wrote to {}", display),
    }
}