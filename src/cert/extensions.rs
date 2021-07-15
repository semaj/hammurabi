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
                            BerObjectContent::Unknown(_bertag, url) => format!("\nCRLDistributionPoint({}, {:?}).", hash, String::from_utf8_lossy((url.split_at(4)).1)),
                            _ => String::from("")
                        }
                    ),
                    _ => None 
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


pub fn emit_authority_info_access(hash: &String, extension: &X509Extension) -> String {
    match parse_der(extension.value) {
        Ok(v) => {
            let authority_info_access_syntax: Vec<BerObject> = match v.1.as_sequence() {
                Ok(objects) => objects.to_vec(),
                Err(..) => vec![]
            };
            let _result: String = authority_info_access_syntax
                .iter()
                .enumerate()
                .filter_map(|(_, point_syntax): (usize, &BerObject<'_>)| match &point_syntax.content {
                    BerObjectContent::Sequence(access_description) => Some(
                        match &access_description[0].content {
                            BerObjectContent::Unknown(_bertag, general_name) => format!("\nauthorityInfoAccessLocation({}, {:?}).", hash, String::from_utf8_lossy(general_name)),
                            _ => String::from("Doesn't get to location")
                        }
                    ),
                    _ => Some(String::from("Doesn't match the point syntax")) //None 
                })
            .collect::<Vec<String>>()
                .join("This isn't working");

            format!("authorityInfoAccessExt({}, true).\nauthorityInfoAccessCritical({}, {}).", hash, hash, extension.critical)
        }
        Err(e) => {
            println!("{:?}", e);
            format!("authorityInfoAccessExt({}, false).\nauthorityInfoAccessCritical({}, {}).", hash, hash, extension.critical)
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
