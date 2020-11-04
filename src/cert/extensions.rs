
use std::collections::HashMap;
use std::str;

use der_parser::ber::{BerObject, BerObjectContent};
use der_parser::parse_der;
use x509_parser::x509::X509Extension;
pub fn emit_key_usage(hash: &String, extension: &X509Extension) -> String {
    // order: digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly
    match parse_der(extension.value) {
        Ok(v) => {
            match &v.1.content {
                BerObjectContent::BitString(_, v) => {
                    let mut answer: String = format!("extensionExists({}, \"KeyUsage\", true).\nextensionCritic({}, \"KeyUsage\", {}).", hash, hash, extension.critical);
                    let prefix: String = format!("\nextensionValues({}, \"KeyUsage\",", hash);

                    // We can pre-bitshift? Yes, but that's not going to happen right now. I don't have an elegant way of doing it easily.
                    answer.push_str(format!("{} \"digitalSignature\", {:?}).", prefix, v.data[0] & 0b10000000 == 0b10000000).as_str());
                    answer.push_str(format!("{} \"nonRepudiation\", {}).", prefix, v.data[0] & 0b1000000 == 0b1000000).as_str());
                    answer.push_str(format!("{} \"keyEncipherment\", {}).", prefix, v.data[0] & 0b100000 == 0b100000).as_str());
                    answer.push_str(format!("{} \"dataEncipherment\", {}).", prefix, v.data[0] & 0b10000 == 0b10000).as_str());
                    answer.push_str(format!("{} \"keyAgreement\", {}).", prefix, v.data[0] & 0b1000 == 0b1000).as_str());
                    answer.push_str(format!("{} \"keyCertSign\", {}).", prefix, v.data[0] & 0b100 == 0b100).as_str());
                    answer.push_str(format!("{} \"cRLSign\", {}).", prefix, v.data[0] & 0b10 == 0b10).as_str());
                    answer.push_str(format!("{} \"encipherOnly\", {}).", prefix, (v.data[0] & 0b1 == 0b1) & (v.data[0] & 0b1000 == 0b1000)).as_str());
                    answer.push_str(format!("{} \"decipherOnly\", {}).", prefix, (v.data[0] & 0b1 == 0b0) & (v.data[0] & 0b1000 == 0b1000)).as_str());
                    answer
                }

                _ => format!("extensionExists({}, \"KeyUsage\", false).", hash)
            }
        }
        Err(e) => {
            println!("{:?}", e);
            format!("extensionExists({}, \"KeyUsage\", false).", hash)
        }
    }
}

pub fn emit_extended_key_usage(hash: &String, extension: &X509Extension) -> String {
    // order serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning
    match parse_der(extension.value) {
        Ok(v) => {
            let mut answer: String = format!("extensionExists({}, \"ExtendedKeyUsage\", true).\nextensionCritic({}, \"ExtendedKeyUsage\", {}).", hash, hash, extension.critical);
            let prefix: String = format!("\nextensionValues({}, \"ExtendedKeyUsage\",", hash);

            let mapping: HashMap<String, bool> = match &v.1.content {
                BerObjectContent::Sequence(content) => {
                    let aggregator: HashMap<String, bool> = content
                        .iter()
                        .map(|x| match &x.content {
                            BerObjectContent::OID(case) => (case.to_string(), true),
                            _ => (String::from("failure"), false),
                        })
                    .collect();
                aggregator
                }
                _ => HashMap::new(),
            };

            answer.push_str(format!("{} \"serverAuth\", {}).", prefix, *mapping.get(&String::from("1.3.6.1.5.5.7.3.1")).unwrap_or(&false)).as_str());
            answer.push_str(format!("{} \"clientAuth\", {}).", prefix, *mapping.get(&String::from("1.3.6.1.5.5.7.3.2")).unwrap_or(&false)).as_str());
            answer.push_str(format!("{} \"codeSigning\", {}).", prefix, *mapping.get(&String::from("1.3.6.1.5.5.7.3.3")).unwrap_or(&false)).as_str());
            answer.push_str(format!("{} \"emailProtection\", {}).", prefix, *mapping.get(&String::from("1.3.6.1.5.5.7.3.4")).unwrap_or(&false)).as_str());
            answer.push_str(format!("{} \"timeStamping\", {}).", prefix, *mapping.get(&String::from("1.3.6.1.5.5.7.3.8")).unwrap_or(&false)).as_str());
            answer.push_str(format!("{} \"OCSPSigning\", {}).", prefix, *mapping.get(&String::from("1.3.6.1.5.5.7.3.9")).unwrap_or(&false)).as_str());
            answer
        }
        Err(e) => {
            println!("{:?}", e);
            format!("extensionExists({}, \"ExtendedKeyUsage\", false).", hash)
        }
    }
}

pub fn emit_basic_constraints(hash: &String, extension: &X509Extension) -> String {
    match parse_der(extension.value) {
        Ok(v) => {
            let mut answer: String = format!("extensionExists({}, \"BasicConstraints\", true).
extensionCritic({}, \"BasicConstraints\", {}).", hash, hash, extension.critical);

            let mut items: Vec<String> = match v.1.as_sequence() {
                Ok(objects) => objects
                    .iter()
                    .map(|f: &BerObject<'_>| match f.class {
                        0 => match f.content.as_bool() {
                            Ok(v) => format!("{}", v),
                            Err(_) => match f.content.as_u32() {
                                Ok(v) => format!("{}", v),
                                Err(e) => format!("{:?}", e),
                            },
                        }
                        1 => match f.content.as_u32() {
                            Ok(v) => format!("{}", v),
                            Err(_) => String::from("none")
                        },
                        _ => format!("Should not have gotten this! {}", f.class),
                    })
                .collect::<Vec<String>>(),
                Err(e) => vec![format!("{:?}", e)],
            };
            if items.len() < 2 {
                items.push(String::from("none"));
            }
            let result: String = items
                .iter()
                .map(|item| format!("{}, ", item))
                .collect::<String>()
                .trim_end_matches(", ")
                .to_string();

            answer.push_str(format!("\nextensionValues({}, \"BasicConstraints\", {}).", hash, result).as_str());
            answer
        }
        Err(_) => format!("extensionExists({}, \"BasicConstraints\", false).", hash)
    }
}

pub fn emit_subject_key_identifier(hash: &String, extension: &X509Extension) -> String {
    match parse_der(extension.value) {
        Ok(v) => {
            let string_id: String = match v.1.content {
                BerObjectContent::OctetString(v) => {
                    let hex_identifier =
                        v.iter().map(|&s| format!("{:02x}:", s)).collect::<String>();
                    String::from(hex_identifier.trim_end_matches(":"))
                }
                _ => String::from("00"),
            };

            format!("extensionExists({}, \"SubjectKeyIdentifier\", true).
extensionCritic({}, \"SubjectKeyIdentifier\", {}).
extensionValues({}, \"SubjectKeyIdentifier\", \"{}\").", hash, hash, extension.critical, hash, string_id)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("extensionExists({}, \"SubjectKeyIdentifier\", false).
extensionCritic({}, \"SubjectKeyIdentifier\", {}).", hash, hash, extension.critical)
        }
    }
}

pub fn emit_subject_alternative_names(hash: &String, extension: &X509Extension) -> String {
    match parse_der(extension.value) {
        Ok(v) => {
            let names: Vec<String> = match v.1.as_sequence() {
                Ok(objects) => objects
                    .iter()
                    .map(|f: &BerObject<'_>| match f.class {
                        2 => match str::from_utf8(f.content.as_slice().unwrap()) {
                            Ok(t) => format!("{}", t),
                            Err(e) => {
                                eprintln!("SAN parsing error: {}", e);
                                format!("")
                            },
                        },
                        _ => format!("Should not have gotten this! {}", f.class),
                    })
                .collect::<Vec<String>>(),
                Err(e) => vec![format!("{:?}", e)],
            };
            let result: String = names
                .iter()
                .map(|name| format!("\nextensionValues({}, \"SubjectAlternativeNames\", \"{}\").", hash, name.to_lowercase().replace("\"", "\\\"")))
                .collect::<String>()
                .to_string();

            format!("extensionExists({}, \"SubjectAlternativeNames\", true).
extensionCritic({}, \"SubjectKeyAlternativeNames\", {}). {}", hash, hash, extension.critical, result)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("extensionExists({}, \"SubjectAlternativeNames\", false).
extensionCritic({}, \"SubjectKeyAlternativeNames\", {}).", hash, hash, extension.critical)
        }
    }
}

pub fn emit_certificate_policies(hash: &String, extension: &X509Extension) -> String {
    match parse_der(extension.value) {
        Ok(v) => {
            let certificate_policies: Vec<BerObject> = match v.1.as_sequence() {
                Ok(objects) => objects.to_vec(),
                Err(..) => vec![]
            };
            let result: String = certificate_policies
                .iter()
                .enumerate()
                .filter_map(|(i, policy): (usize, &BerObject<'_>)| match &policy.content {
                    BerObjectContent::Sequence(policy_info) => Some(
                        match &policy_info[0].content {
                            BerObjectContent::OID(policy_oid) => format!("\nextensionValues({}, \"CertificatePolicies\", \"{}\", {}).", hash, policy_oid.to_owned().to_string(), i),
                            _ => String::from("")
                        }
                    ),
                    _ => None
                })
            .collect::<Vec<String>>()
                .join("");

            format!("extensionExists({}, \"CertificatePolicies\", true).
extensionCritic({}, \"CertificatePolicies\", {}). {}", hash, hash, extension.critical, result)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("extensionExists({}, \"CertificatePolicies\", false).
extensionCritic({}, \"CertificatePolicies\", {}).", hash, hash, extension.critical)
        }
    }
}
