use der_parser::ber::{BerObject, BerObjectContent};
use der_parser::parse_der;
use x509_parser::extensions::{X509Extension};

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
