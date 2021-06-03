use openssl::hash::MessageDigest;
use openssl::ocsp::{
    OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus,
};
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{X509Ref, X509};
use std::time::{Duration, Instant};

pub fn check_ocsp(
    cert_index: u32,
    store: &X509Store,
    subject: &X509Ref,
    issuer: &X509Ref,
    certs: &Stack<X509>,
    check_ocsp: bool,
    staple: bool,
) -> Vec<String> {
    let mut output_facts: Vec<String> = Vec::new();
    let hash = format!("cert_{}", cert_index);

    let responders = match subject.ocsp_responders() {
        Ok(r) => r,
        Err(_) => { return output_facts; }
    };
    if responders.len() == 0 {
        return output_facts;
    }

    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();
    let verify_cert_id = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();

    let mut req = OcspRequest::new().unwrap();
    req.add_id(cert_id).unwrap();
    let req_der = req.to_der().unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/ocsp-request"),
    );

    let client = reqwest::blocking::Client::builder().default_headers(headers).timeout(Duration::new(2, 0)).build().unwrap();

    // Only use the first OCSP URI
    let ocsp_uri = responders.iter().next().unwrap();
    output_facts.push(format!("ocspResponder({}, \"{}\").", hash, ocsp_uri));

    if !check_ocsp {
        output_facts.push(format!("ocspValid({}, \"{}\", false).", hash, ocsp_uri));
        return output_facts;
    }
    // You could use the GET too, if you want.
    //let encoded_req = base64::encode(req_der.clone());
    let before = Instant::now();
    let res = match client.post(&format!("{}", ocsp_uri)).body(req_der.clone()).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("OCSP request error: {}", e);
            output_facts.push(format!("ocspValid({}, false).", hash));
            return output_facts;
        }
    };
    let elapsed = before.elapsed().as_millis();
    eprintln!("OCSP request time: {}ms", elapsed);
    let bytes = match res.bytes() {
        Ok(b) => b,
        Err(_) => {
            eprintln!("OCSP response parsing error!");
            output_facts.push(format!("ocspValid({}, false).", hash));
            return output_facts;
        }
    };
    if staple {
        return ocsp_stapling(Some(&bytes), &store, subject, issuer, certs);
    }
    let ocsp_response_result = OcspResponse::from_der(&bytes);
    if ocsp_response_result.is_err() {
        output_facts.push(format!("ocspValid({}, false).", hash));
        return output_facts;
    }
    let ocsp_response = ocsp_response_result.unwrap();
    let ocsp_basic_response = match ocsp_response.basic() {
        Ok(basic_response) => {
            output_facts.push(format!("ocspValid({}, true).", hash));
            basic_response
        }
        Err(e) => {
            eprintln!("OCSP response error: {}, error code: {}", e, ocsp_response.status().as_raw());
            // See: https://tools.ietf.org/html/rfc6960#section-4.2.1 for status codes
            if ocsp_response.status() != OcspResponseStatus::INTERNAL_ERROR
                && ocsp_response.status() != OcspResponseStatus::TRY_LATER
                && ocsp_response.status() != OcspResponseStatus::UNAUTHORIZED
            {
                eprintln!("OCSP Response Status: {}", ocsp_response.status().as_raw());
                //panic!("Problem sending OCSP request.");
            }
            output_facts.push(format!("ocspValid({}, false).", hash));
            return output_facts;
        }
    };
    match ocsp_basic_response.verify(certs.as_ref(), store, OcspFlag::empty()) {
        Ok(_) => output_facts.push(format!("ocspVerified({}, true).", hash)),
        Err(error_stack) => {
            eprintln!("Verification failed for URI {}. Error stack: {}", ocsp_uri, error_stack);
            output_facts.push(format!("ocspVerified({}, false).", hash));
            return output_facts;
        }
    }
    // Perhaps, rather than panicing on None, we should emit an UNKNOWN status?
    let ocsp_status = ocsp_basic_response.find_status(verify_cert_id.as_ref()).unwrap();

    // Allow for 1s (1e9 ns) clock skew.
    match ocsp_status.check_validity(1000000000, None) {
        Ok(_) => output_facts.push(format!("ocspExpired({}, false).", hash)),
        Err(error_stack) => {
            eprintln!("Validation failed for URI {}. Error stack: {}", ocsp_uri, error_stack);
            output_facts.push(format!("ocspExpired({}, true).", hash));
            return output_facts;
        }
    }
    match ocsp_status.status {
        OcspCertStatus::GOOD => {
            output_facts.push(format!( "ocspStatus({}, good).", hash));
        }
        OcspCertStatus::REVOKED => {
            output_facts.push(format!( "ocspStatus({}, revoked).", hash));
        }
        OcspCertStatus::UNKNOWN => {
            output_facts.push(format!( "ocspStatus({}, unknown).", hash));
        }
        // Do not break, since perhaps the other responders know.
        _ => panic!("OCSPCertStatus is an unknown value."),
    }

    return output_facts;
}

pub fn ocsp_stapling(
    stapled_ocsp_response: Option<&[u8]>,
    store: &X509Store,
    subject: &X509Ref,
    issuer: &X509Ref,
    certs: &Stack<X509>,
) -> Vec<String> {
    let hash = "cert_0".to_string();
    let mut output_facts: Vec<String> = Vec::new();
    let ocsp_response: OcspResponse = match stapled_ocsp_response {
        Some(raw) => OcspResponse::from_der(raw).unwrap(),
        None => {
            output_facts.push(format!("stapledOcspPresent({}, false).", hash));
            return output_facts;
        }
    };
    output_facts.push(format!("stapledOcspPresent({}, true).", hash));
    let verify_cert_id = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();

    let ocsp_basic_response = match ocsp_response.basic() {
        Ok(basic_response) => {
            output_facts.push(format!("stapledOcspValid({}, true).", hash));
            basic_response
        }
        Err(_) => {
            output_facts.push(format!("stapledOcspValid({}, false).", hash));
            return output_facts;
        }
    };
    match ocsp_basic_response.verify(certs.as_ref(), store, OcspFlag::empty()) {
        Ok(_) => output_facts.push(format!("stapledOcspVerified({}, true).", hash)),
        Err(error_stack) => {
            eprintln!(
                "Verification failed for stapled OCSP response. Error stack: {}",
                error_stack
            );
            output_facts.push(format!("stapledOcspVerified({}, false).", hash));
            return output_facts;
        }
    }
    // Perhaps, rather than panicing on None, we should emit an UNKNOWN status?
    let ocsp_status = ocsp_basic_response
        .find_status(verify_cert_id.as_ref())
        .unwrap();
    // Allow for 1s (1e9 ns) clock skew.
    match ocsp_status.check_validity(1000000000, None) {
        Ok(_) => output_facts.push(format!("stapledOcspExpired({}, false).", hash)),
        Err(error_stack) => {
            eprintln!(
                "Validation failed for stapled ocsp response. Error stack: {}",
                error_stack
            );
            output_facts.push(format!("stapledOcspExpired({}, true).", hash));
            return output_facts;
        }
    }
    match ocsp_status.status {
        OcspCertStatus::GOOD => {
            output_facts.push(format!("stapledOcspStatus({}, good).", hash));
        }
        OcspCertStatus::REVOKED => {
            output_facts.push(format!("stapledOcspStatus({}, revoked).", hash));
        }
        OcspCertStatus::UNKNOWN => {
            output_facts.push(format!("stapledOcspStatus({}, unknown).", hash))
        }
        // Do not break, since perhaps the other responders know.
        _ => panic!("OCSPCertStatus is an unknown value."),
    }
    return output_facts;
}
