
use hex;
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509VerifyResult, X509};
use std::{fs, env};
use std::io::Write;
use std::time::Instant;
use std::process::Command;
use x509_parser::pem::pem_to_der;

mod cert;
mod revocation;

mod errors;
use errors::Error;

const DATALOG_GEN_DIR: &'static str = "datalog/gen";

pub fn verify_prolog(
    chain: &mut Vec<X509>,
    dns_name: &str,
    stapled_ocsp_response: Option<&[u8]>,
    check_ocsp: bool,
) -> Result<(), Error> {
    let start = Instant::now();

    let mut counter = 0;
    let leaf = chain.remove(0);
    let leaf_der = leaf.to_der().unwrap();
    let cert = match cert::PrologCert::from_der(&leaf_der) {
        Ok(p) => p,
        Err(_) => {
            return Err(Error::X509ParsingError);
        },
    };
    let mut repr: String = cert.emit_all(&format!("cert_{}", counter));
    let mut fingerprints: Vec<String> = Vec::new();

    let mut stack = Stack::new().unwrap();
    let mut recursive_subject = leaf.clone();

    for intermediate_x509 in chain.iter() {
        counter += 1;
        match recursive_subject.verify(&intermediate_x509.public_key().unwrap()) {
            Ok(true) => {},
            Ok(false) => return Err(Error::OpenSSLInvalid),
            Err(e) => {
                eprintln!("OpenSSL Verify error {}", e);
                return Err(Error::OpenSSLFailed);
            }
        }
        recursive_subject = intermediate_x509.clone();

        let intermediate_der = intermediate_x509.to_der().unwrap();
        let intermediate = match cert::PrologCert::from_der(&intermediate_der) {
            Ok(p) => p,
            Err(_) => {
                return Err(Error::X509ParsingError);
            },
        };
        repr.push_str(&intermediate.emit_all(&format!("cert_{}", counter)));
        repr.push_str(&format!(
            "fingerprint(cert_{}, \"{}\").\n",
            counter,
            hex::encode(intermediate_x509.digest(MessageDigest::sha256()).unwrap()).to_uppercase()
        ));
        stack.push(intermediate_x509.clone()).unwrap();
        // We just assume (for now) that intermediates
        // do not have stapled ocsp responses.
        repr.push_str(&format!("no_stapled_ocsp_response(cert_{}).\n", counter));
    }

    let mut store_builder = X509StoreBuilder::new().unwrap();

    // get root certs
    let separator = "-----END CERTIFICATE-----";
    let root_chain = fs::read_to_string("assets/roots.pem").unwrap();
    let mut found_issuer = false;
    for part in root_chain.split(separator) {
        if part.trim().is_empty() {
            continue;
        }

        counter += 1;
        let cert_pem = [part, separator].join("");
        let temp = pem_to_der(cert_pem.as_bytes()).unwrap().1.contents;
        let root_x509 = X509::from_der(&temp).unwrap();
        for intermediate_x509 in chain.iter() {
            fingerprints.push(hex::encode(root_x509.digest(MessageDigest::sha256()).unwrap()).to_uppercase());
            if root_x509.issued(&intermediate_x509) == X509VerifyResult::OK {
                found_issuer = true;
                let root_x509_for_stack = X509::from_der(&temp).unwrap();
                stack.push(root_x509_for_stack).unwrap();
                repr.push_str(&format!(
                        "fingerprint(cert_{}, \"{}\").\n",
                        counter,
                        hex::encode(root_x509.digest(MessageDigest::sha256()).unwrap()).to_uppercase()
                ));
                let v = match cert::PrologCert::from_der(&temp) {
                    Ok(p) => p,
                    Err(_) => {
                        return Err(Error::X509ParsingError);
                    },
                };
                repr.push_str(&v.emit_all(&format!("cert_{}", counter)));
            }
        }

        store_builder.add_cert(root_x509).unwrap();
    }
    if !found_issuer {
        eprintln!("NO ISSUER FOUND");
    }
    let issuer_x509 = &chain[0];
    let subject_x509 = leaf;
    let sha256 = hex::encode(subject_x509.digest(MessageDigest::sha256()).unwrap());
    repr.push_str(&format!(
        "fingerprint(cert_0, \"{}\").\n",
        sha256.to_uppercase()
    ));

    let store = store_builder.build();

    repr.push_str(
        &revocation::ocsp_stapling(
            stapled_ocsp_response,
            &store,
            &subject_x509,
            issuer_x509,
            &stack,
        )
        .join("\n"),
    );
    repr.push_str("\n\n");

    let mut subject_ref = subject_x509.as_ref();
    let mut cert_index = 0;
    for intermediate_ref in stack.iter() {
        repr.push_str(
            &revocation::check_ocsp(cert_index, &store, subject_ref, intermediate_ref, &stack, check_ocsp)
                .join("\n"),
        );
        repr.push_str("\n\n");
        subject_ref = intermediate_ref;
        cert_index += 1;
    }

    let elapsed = start.elapsed().as_millis();
    println!("Rust/OpenSSL execution time (ms): {}", elapsed);

    let key = "JOBINDEX";
    let jobindex = env::var(key).unwrap_or("".to_string());
    let roots: String = fingerprints
        .iter()
        .map(|name| format!("\ntrusted_roots(\"{}\").", name))
        .collect::<String>()
        .to_string();
    let name = format!("{}/env.pl", DATALOG_GEN_DIR);
    let mut kb_env = fs::File::create(name).expect("failed to create file"); kb_env
        .write_all(emit_env_preamble().as_bytes())
        .expect("failed to write message");
    kb_env.write_all(roots.as_bytes()).expect("failed to write message");
    kb_env.sync_all().unwrap();

    let name = format!("{}/certs{}.pl", DATALOG_GEN_DIR, jobindex);
    let mut kb_cert = fs::File::create(name).expect("failed to create file");
    kb_cert
        .write_all(emit_kb_cert_preamble().as_bytes())
        .expect("failed to write message");
    kb_cert
        .write_all(repr.as_bytes())
        .expect("failed to write message");
    kb_cert.sync_all().unwrap();

    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("datalog/query.sh cert_0 {}", dns_name))
        .status()
        .expect("failed to execute process");

    let status = status.code().unwrap();
    match status {
        0 => Ok(()),
        10 => Err(Error::CertNotTimeValid),
        20 => Err(Error::NameConstraintViolation),
        30 => Err(Error::CertNotValidForName),
        40 => Err(Error::CertRevoked),
        50 => Err(Error::PathLenConstraintViolated),
        60 => Err(Error::UnknownIssuer),
        70 => Err(Error::ACCFailure),
        80 => Err(Error::LeafValidForTooLong),
        _ => Err(Error::UnknownError)
    }
}

fn emit_kb_cert_preamble() -> String {
    format!(
        ":- module(certs, [
        issuer/6,
        validity/3,
        subject/6,
        extensionExists/3,
        extensionCritic/3,
        extensionValues/3,
        extensionValues/4,
        serialNumber/2,
        version/2,
        keyAlgorithm/2,
        keyLen/2,
        signatureAlgorithm/2,
        no_stapled_ocsp_response/1,
        stapled_ocsp_response/1,
        stapled_ocsp_response_verified/1,
        stapled_ocsp_response_valid/1,
        stapled_ocsp_response_not_expired/1,
        stapled_ocsp_response_not_verified/1,
        stapled_ocsp_response_invalid/1,
        stapled_ocsp_response_expired/1,
        stapled_ocsp_status_revoked/1,
        stapled_ocsp_status_unknown/1,
        stapled_ocsp_status_good/1,
        ocsp_responder/2,
        no_ocsp_responders/1,
        ocsp_response_verified/2,
        ocsp_response_valid/2,
        ocsp_response_not_expired/2,
        ocsp_response_not_verified/2,
        ocsp_response_invalid/2,
        ocsp_response_expired/2,
        ocsp_status_revoked/2,
        ocsp_status_unknown/2,
        ocsp_status_good/2,
        fingerprint/2
    ]).
:-style_check(-discontiguous).
no_stapled_ocsp_response(hack).
stapled_ocsp_response(hack).
stapled_ocsp_response_verified(hack).
stapled_ocsp_response_valid(hack).
stapled_ocsp_response_not_expired(hack).
stapled_ocsp_response_not_verified(hack).
stapled_ocsp_response_invalid(hack).
stapled_ocsp_response_verified(hack).
stapled_ocsp_response_expired(hack).
stapled_ocsp_status_revoked(hack).
stapled_ocsp_status_unknown(hack).
stapled_ocsp_status_good(hack).
ocsp_responder(hack, hack).
no_ocsp_responders(hack).
ocsp_response_verified(hack, hack).
ocsp_response_valid(hack, hack).
ocsp_response_not_expired(hack, hack).
ocsp_response_not_verified(hack, hack).
ocsp_response_invalid(hack, hack).
ocsp_response_expired(hack, hack).
ocsp_status_revoked(hack, hack).
ocsp_status_unknown(hack, hack).
ocsp_status_good(hack, hack).\n\n"
    )
}

fn emit_env_preamble() -> String {
    format!(
        ":- module(env, [
        tlsVersion/1,
        max_intermediates/1,
        hostIp/1
    ]).

:- use_module(std, [ipToNumber/6]).
:- style_check(-discontiguous).

tlsVersion(2).
max_intermediates(5).
hostIp(H):-
    ipToNumber(192,168,1,1,0,H).\n",
    )
}

