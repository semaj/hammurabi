use der_parser::ber::{BerObject, BerObjectContent};
use der_parser::parse_der;
use x509_parser::extensions::{X509Extension};
//use x509_parser::extensions::GeneralName;

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

            format!("subjectKeyIdentifierExt({}, true).
subjectKeyIdentifierCritical({}, {}).
subjectKeyIdentifier({}, \"{}\").", hash, hash, extension.critical, hash, string_id)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("subjectKeyIdentifierExt({}, false).
subjectKeyIdentifierCritical({}, {}).", hash, hash, extension.critical)
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
                .filter_map(|(_, policy): (usize, &BerObject<'_>)| match &policy.content {
                    BerObjectContent::Sequence(policy_info) => Some(
                        match &policy_info[0].content {
                            BerObjectContent::OID(policy_oid) => format!("\ncertificatePolicies({}, \"{}\").", hash, policy_oid.to_owned().to_string()),
                            _ => String::from("")
                        }
                    ),
                    _ => None
                })
            .collect::<Vec<String>>()
                .join("");

            format!("certificatePoliciesExt({}, true).\ncertificatePoliciesCritical({}, {}). {}", hash, hash, extension.critical, result)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("certificatePoliciesExt({}, false).\ncertificatePoliciesCritical({}, {}).", hash, hash, extension.critical)
        }
    }
}

pub fn emit_crl_distribution_points(hash: &String, extension: &X509Extension) -> String {
    match parse_der(extension.value) {
        Ok(v) => {
            let crl_distribution_points: Vec<BerObject> = match v.1.as_sequence() {
                Ok(objects) => objects.to_vec(),
                Err(..) => vec![]
            };
            let result: String = crl_distribution_points
                .iter()
                .enumerate()
                .filter_map(|(_, point_syntax): (usize, &BerObject<'_>)| match &point_syntax.content {
                    BerObjectContent::Sequence(distribution_point) => Some(
                        match &distribution_point[0].content {
                            BerObjectContent::Unknown(url, url2) => format!("\nCRLDistributionPointName({}, {:?}, \"{:?}\").", hash, url, url2),
                            _ => String::from("This still doesn't work")//, print!()
                            //_ => String::from("This match doesn't work")
                        }
                            
                                   
                        //match &distribution_point[0].content {

                            //choice not oid or other
                            //BerObjectContent::PrintableString(url) => format!("\nCRLDistributionPoints({}, \"{}\").", hash, url),
                            //_ => String::from("")
                        //}
                        //println!("{:?}", distribution_point)
                    ),
                    _ => None //Some(String::from("The first match did not work"))//println!("The first match did not work") 
                })
            .collect::<Vec<String>>()
                .join("");

            format!("CRLDistributionPointsExt({}, true).\nCRLDistributionPointsCritical({}, {}). {}", hash, hash, extension.critical, result)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("CRLDistributionPointsExt({}, false).\nCRLDistributionPointsCritical({}, {}).", hash, hash, extension.critical)
        }
    }
}

pub fn emit_acc_assertions(hash: &String, extension: &X509Extension) -> String {
    let mut assertions = std::str::from_utf8(extension.value).unwrap().to_string();
    assertions = str::replace(&assertions, "!!!", hash);
    return assertions
    //match parse_der(extension.value) {
        //Ok(v) => {
            //let assertions: String = match std::str::from_utf8(v.1.as_slice().unwrap()) {
                //Ok(objects) => format!("{}", objects),
                //Err(e) => format!("{:?}", e),
            //};

            //str::replace(&assertions, "!!!", hash)
        //}
        //Err(_) => format!("extensionExists({}, \"Assertion\", false).", hash)
    //}
}
