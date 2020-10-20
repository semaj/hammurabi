use std::time::{Duration, Instant};
use openssl::hash::MessageDigest;
use openssl::ocsp::{
    OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus,
};
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{X509Ref, X509};

pub fn check_ocsp(
    cert_index: u32, store: &X509Store, subject: &X509Ref, issuer: &X509Ref, certs: &Stack<X509>, check_ocsp: bool,
) -> Vec<String> {
    let mut output_facts: Vec<String> = Vec::new();
    let cert_identifier = format!("cert_{}", cert_index);

    let ocsp_responders = match subject.ocsp_responders() {
        Ok(responders) => responders,
        Err(_) => {
            // OCSP is unsupported
            return output_facts;
        }
    };

    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();
    let verification_cert_id =
        OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();
    let mut req = OcspRequest::new().unwrap();
    let sha256 = hex::encode(subject.digest(MessageDigest::sha256()).unwrap());
    req.add_id(cert_id).unwrap();
    let req_der = req.to_der().unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/ocsp-request"),
    );
    let client = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .timeout(Duration::new(2, 0))
        .build()
        .unwrap();
    if ocsp_responders.len() == 0 {
        output_facts.push(format!("no_ocsp_responders({}).", cert_identifier));
        return output_facts;
    }

    for (i, ocsp_uri) in ocsp_responders.iter().enumerate() {
        // Only use the first OCSP URI
        if i != 0 {
            break;
        }
        // Each OCSP URI gets its own fact (for a given cert).
        output_facts.push(format!(
            "ocsp_responder({}, \"{}\").",
            cert_identifier, ocsp_uri
        ));
        if !check_ocsp {
            output_facts.push(format!(
                    "ocsp_response_invalid({}, \"{}\").",
                    cert_identifier, ocsp_uri
            ));
            continue;
        }
        // You could use the GET too, if you want.
        //let encoded_req = base64::encode(req_der.clone());
        let before = Instant::now();
        let res = match client
            .post(&format!("{}", ocsp_uri))
            .body(req_der.clone())
            .send() {
                Ok(r) => r,
                Err(_) => {
                    output_facts.push(format!(
                            "ocsp_response_invalid({}, \"{}\").",
                            cert_identifier, ocsp_uri
                    ));
                    continue;
                },
        };
        let elapsed = before.elapsed().as_millis();
        eprintln!("{} OCSP Check URI elapsed {}ms", sha256, elapsed);
        let bytes = res.bytes();
        let bytes = match bytes {
            Ok(b) => b,
            Err(_) => {
                eprintln!("OCSP response parsing error!");
                output_facts.push(format!(
                        "ocsp_response_invalid({}, \"{}\").",
                        cert_identifier, ocsp_uri
                ));
                continue;
            },
        };
        let ocsp_response_result = OcspResponse::from_der(&bytes);
        if ocsp_response_result.is_err() {
            output_facts.push(format!(
                "ocsp_response_invalid({}, \"{}\").",
                cert_identifier, ocsp_uri
            ));
            continue;
        }
        let ocsp_response = ocsp_response_result.unwrap();
        let ocsp_basic_response = match ocsp_response.basic() {
            Ok(basic_response) => {
                output_facts.push(format!(
                    "ocsp_response_valid({}, \"{}\").",
                    cert_identifier, ocsp_uri
                ));
                basic_response
            }
            Err(_) => {
                // See: https://tools.ietf.org/html/rfc6960#section-4.2.1 for status codes
                if ocsp_response.status() != OcspResponseStatus::INTERNAL_ERROR
                    && ocsp_response.status() != OcspResponseStatus::TRY_LATER
                    && ocsp_response.status() != OcspResponseStatus::UNAUTHORIZED
                {
                    eprintln!("OCSP Response Status: {}", ocsp_response.status().as_raw());
                    //panic!("Problem sending OCSP request.");
                }
                output_facts.push(format!(
                    "ocsp_response_invalid({}, \"{}\").",
                    cert_identifier, ocsp_uri
                ));
                continue;
            }
        };
        match ocsp_basic_response.verify(certs.as_ref(), store, OcspFlag::empty()) {
            Ok(_) => output_facts.push(format!(
                "ocsp_response_verified({}, \"{}\").",
                cert_identifier, ocsp_uri
            )),
            Err(error_stack) => {
                eprintln!(
                    "Verification failed for URI {}. Error stack: {}",
                    ocsp_uri, error_stack
                );
                output_facts.push(format!(
                    "ocsp_response_not_verified({}, \"{}\").",
                    cert_identifier, ocsp_uri
                ));
                continue; // Try the next URI.
            }
        }
        // Perhaps, rather than panicing on None, we should emit an UNKNOWN status?
        let ocsp_status = ocsp_basic_response
            .find_status(verification_cert_id.as_ref())
            .unwrap();
        // Allow for 1s (1e9 ns) clock skew.
        match ocsp_status.check_validity(1000000000, None) {
            Ok(_) => output_facts.push(format!(
                "ocsp_response_not_expired({}, \"{}\").",
                cert_identifier, ocsp_uri
            )),
            Err(error_stack) => {
                eprintln!(
                    "Validation failed for URI {}. Error stack: {}",
                    ocsp_uri, error_stack
                );
                output_facts.push(format!(
                    "ocsp_response_expired({}, \"{}\").",
                    cert_identifier, ocsp_uri
                ));
                continue;
            }
        }
        match ocsp_status.status {
            OcspCertStatus::GOOD => {
                output_facts.push(format!(
                    "ocsp_status_good({}, \"{}\").",
                    cert_identifier, ocsp_uri
                ));
                //break;
            }
            OcspCertStatus::REVOKED => {
                output_facts.push(format!(
                    "ocsp_status_revoked({}, \"{}\").",
                    cert_identifier, ocsp_uri
                ));
                //break;
            }
            OcspCertStatus::UNKNOWN => output_facts.push(format!(
                "ocsp_status_unknown({}, \"{}\").",
                cert_identifier, ocsp_uri
            )),
            // Do not break, since perhaps the other responders know.
            _ => panic!("OCSPCertStatus is an unknown value."),
        }
    }
    return output_facts;
}

pub fn ocsp_stapling(
    stapled_ocsp_response: Option<&[u8]>, store: &X509Store, subject: &X509, issuer: &X509,
    certs: &Stack<X509>,
) -> Vec<String> {
    let cert_identifier = "cert_0".to_string();
    let mut output_facts: Vec<String> = Vec::new();
    let ocsp_response: OcspResponse = match stapled_ocsp_response {
        Some(raw) => OcspResponse::from_der(raw).unwrap(),
        None => {
            output_facts.push(format!("no_stapled_ocsp_response({}).", cert_identifier));
            return output_facts;
        }
    };
    output_facts.push(format!("stapled_ocsp_response({}).", cert_identifier));
    let verification_cert_id =
        OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();
    let ocsp_basic_response = match ocsp_response.basic() {
        Ok(basic_response) => {
            output_facts.push(format!("stapled_ocsp_response_valid({}).", cert_identifier));
            basic_response
        }
        Err(_) => {
            output_facts.push(format!(
                "stapled_ocsp_response_invalid({}).",
                cert_identifier
            ));
            return output_facts;
        }
    };
    match ocsp_basic_response.verify(certs.as_ref(), store, OcspFlag::empty()) {
        Ok(_) => output_facts.push(format!(
            "stapled_ocsp_response_verified({}).",
            cert_identifier
        )),
        Err(error_stack) => {
            eprintln!(
                "Verification failed for stapled OCSP response. Error stack: {}",
                error_stack
            );
            output_facts.push(format!(
                "stapled_ocsp_response_not_verified({}).",
                cert_identifier
            ));
            return output_facts;
        }
    }
    // Perhaps, rather than panicing on None, we should emit an UNKNOWN status?
    let ocsp_status = ocsp_basic_response
        .find_status(verification_cert_id.as_ref())
        .unwrap();
    // Allow for 1s (1e9 ns) clock skew.
    match ocsp_status.check_validity(1000000000, None) {
        Ok(_) => output_facts.push(format!(
            "stapled_ocsp_response_not_expired({}).",
            cert_identifier
        )),
        Err(error_stack) => {
            eprintln!(
                "Validation failed for stapled ocsp response. Error stack: {}",
                error_stack
            );
            output_facts.push(format!(
                "stapled_ocsp_response_expired({}).",
                cert_identifier
            ));
            return output_facts;
        }
    }
    match ocsp_status.status {
        OcspCertStatus::GOOD => {
            output_facts.push(format!("stapled_ocsp_status_good({}).", cert_identifier));
        }
        OcspCertStatus::REVOKED => {
            output_facts.push(format!("stapled_ocsp_status_revoked({}).", cert_identifier));
        }
        OcspCertStatus::UNKNOWN => {
            output_facts.push(format!("stapled_ocsp_status_unknown({}).", cert_identifier))
        }
        // Do not break, since perhaps the other responders know.
        _ => panic!("OCSPCertStatus is an unknown value."),
    }
    return output_facts;
}

