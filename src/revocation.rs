use openssl::hash::MessageDigest;
use openssl::ocsp::{
    OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus,
};
use openssl::stack::Stack;
use openssl::string::OpensslString;
use openssl::x509::store::X509Store;
use openssl::x509::{X509Ref, X509};
use std::time::{Duration, Instant};
use std::{env, fs};

struct OcspResult {
    valid: bool,
    expired: Option<bool>,
    verified: Option<bool>,
    status_ok: Option<bool>,
}

impl OcspResult {
    fn to_string(&self) -> String {
        let valid = match self.valid {
            true => "valid",
            false => "invalid",
        };
        let expired = match self.expired {
            None => "unknown",
            Some(true) => "expired",
            Some(false) => "not_expired",
        };
        let verified = match self.verified {
            None => "unknown",
            Some(true) => "verified",
            Some(false) => "not_verified",
        };
        let status = match self.status_ok {
            None => "unknown",
            Some(true) => "good",
            Some(false) => "revoked",
        };

        format!("[{}, {}, {}, {}]", valid, expired, verified, status)
    }
}

pub fn get_ocsp_fact(
    cert_index: u32,
    store: &X509Store,
    subject: &X509Ref,
    issuer: &X509Ref,
    certs: &Stack<X509>,
    check_ocsp: bool,
    check_staple: bool,
) -> String {
    let hash = format!("cert_{}", cert_index);
    if !check_ocsp {
        return format!("ocspResponse({}, []).\nstapledResponse({}, []).\n", hash, hash);
    }

    let responders = match subject.ocsp_responders() {
        Ok(r) => r,
        Err(_) => {
            return String::from("");
        }
    };
    if responders.len() == 0 {
        return String::from("");
    }
    let mock = env::var("MOCK").unwrap_or("".to_string());
    //let ints = fs::read("/tmp/real-issuer.pem").unwrap_or("".to_string());
    let chain;
    let mut stack;
    let mut actual_subject = subject;
    let mut actual_issuer = issuer;
    let mut actual_certs = certs;
    if mock == "true" {
        // This is needed because when testing our own "frankencerts",
        // OCSP requests will be invalid. We need to use the real
        // subject and issuer
        let ints = fs::read("/tmp/real.pem").unwrap();
        chain = X509::stack_from_pem(&ints).unwrap();
        actual_subject = &chain[0];
        actual_issuer = &chain[1];
        stack = Stack::new().unwrap();
        stack.push(chain[1].clone()).unwrap();
        actual_certs = &stack;
    }

    let fact = match check_staple {
        true => format!("ocspResponse({}, []).\nstapledResponse", hash),
        false => format!("stapledResponse({}, []).\nocspResponse", hash),
    };
    match get_ocsp_response(
        store,
        actual_subject,
        actual_issuer,
        actual_certs,
        &responders,
        check_staple,
    ) {
        None => String::from(""),
        Some(r) => format!("{}({}, {}).\n", fact, hash, r.to_string()),
    }
}

fn get_ocsp_response(
    store: &X509Store,
    subject: &X509Ref,
    issuer: &X509Ref,
    certs: &Stack<X509>,
    responders: &Stack<OpensslString>,
    check_staple: bool,
) -> Option<OcspResult> {
    let mut response = OcspResult {
        valid: false,
        expired: None,
        verified: None,
        status_ok: None,
    };
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

    let client = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .timeout(Duration::new(2, 0))
        .build()
        .unwrap();

    // Only use the first OCSP URI
    let ocsp_uri = responders.iter().next().unwrap();

    // You could use the GET too, if you want.
    //let encoded_req = base64::encode(req_der.clone());
    let before = Instant::now();
    let res = match client
        .post(&format!("{}", ocsp_uri))
        .body(req_der.clone())
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("OCSP request error: {}", e);
            return None;
        }
    };
    let elapsed = before.elapsed().as_millis();
    println!("OCSP request time: {}ms", elapsed);
    let bytes = match res.bytes() {
        Ok(b) => b,
        Err(_) => {
            eprintln!("OCSP response parsing error!");
            return Some(response);
        }
    };
    if check_staple {
        return get_stapled_ocsp_response(Some(&bytes), &store, subject, issuer, certs);
    }
    let ocsp_response_result = OcspResponse::from_der(&bytes);
    if ocsp_response_result.is_err() {
        return Some(response);
    }
    let ocsp_response = ocsp_response_result.unwrap();
    let ocsp_basic_response = match ocsp_response.basic() {
        Ok(basic_response) => {
            response.valid = true;
            basic_response
        }
        Err(e) => {
            eprintln!(
                "OCSP response error: {}, error code: {}",
                e,
                ocsp_response.status().as_raw()
            );
            // See: https://tools.ietf.org/html/rfc6960#section-4.2.1 for status codes
            if ocsp_response.status() != OcspResponseStatus::INTERNAL_ERROR
                && ocsp_response.status() != OcspResponseStatus::TRY_LATER
                && ocsp_response.status() != OcspResponseStatus::UNAUTHORIZED
            {
                eprintln!("OCSP Response Status: {}", ocsp_response.status().as_raw());
                //panic!("Problem sending OCSP request.");
            }
            return Some(response);
        }
    };
    response.verified = match ocsp_basic_response.verify(certs.as_ref(), store, OcspFlag::empty()) {
        Ok(_) => Some(true),
        Err(error_stack) => {
            eprintln!(
                "Verification failed for URI {}. Error stack: {}",
                ocsp_uri, error_stack
            );
            Some(false)
        }
    };
    // Perhaps, rather than panicing on None, we should emit an UNKNOWN status?
    let ocsp_status = ocsp_basic_response
        .find_status(verify_cert_id.as_ref())
        .unwrap();

    // Allow for 1s (1e9 ns) clock skew.
    response.expired = match ocsp_status.check_validity(1000000000, None) {
        Ok(_) => Some(false),
        Err(error_stack) => {
            eprintln!(
                "Validation failed for URI {}. Error stack: {}",
                ocsp_uri, error_stack
            );
            Some(true)
        }
    };
    response.status_ok = match ocsp_status.status {
        OcspCertStatus::GOOD => Some(true),
        OcspCertStatus::REVOKED => Some(false),
        OcspCertStatus::UNKNOWN => None,
        // Do not break, since perhaps the other responders know.
        _ => panic!("OCSPCertStatus is an unknown value."),
    };

    Some(response)
}

fn get_stapled_ocsp_response(
    stapled_ocsp_response: Option<&[u8]>,
    store: &X509Store,
    subject: &X509Ref,
    issuer: &X509Ref,
    certs: &Stack<X509>,
) -> Option<OcspResult> {
    let ocsp_response: OcspResponse = match stapled_ocsp_response {
        Some(raw) => OcspResponse::from_der(raw).unwrap(),
        None => {
            return None;
        }
    };
    let verify_cert_id = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).unwrap();
    let mut response = OcspResult {
        valid: false,
        expired: None,
        verified: None,
        status_ok: None,
    };

    let ocsp_basic_response = match ocsp_response.basic() {
        Ok(basic_response) => {
            response.valid = true;
            basic_response
        }
        Err(_) => {
            return Some(response);
        }
    };
    response.verified = match ocsp_basic_response.verify(certs.as_ref(), store, OcspFlag::empty()) {
        Ok(_) => Some(true),
        Err(error_stack) => {
            eprintln!(
                "Verification failed for stapled OCSP response. Error stack: {}",
                error_stack
            );
            Some(false)
        }
    };
    // Perhaps, rather than panicing on None, we should emit an UNKNOWN status?
    let ocsp_status = ocsp_basic_response
        .find_status(verify_cert_id.as_ref())
        .unwrap();
    // Allow for 1s (1e9 ns) clock skew.
    response.expired = match ocsp_status.check_validity(1000000000, None) {
        Ok(_) => Some(false),
        Err(error_stack) => {
            eprintln!(
                "Validation failed for stapled ocsp response. Error stack: {}",
                error_stack
            );
            Some(true)
        }
    };

    response.status_ok = match ocsp_status.status {
        OcspCertStatus::GOOD => Some(true),
        OcspCertStatus::REVOKED => Some(false),
        OcspCertStatus::UNKNOWN => None,
        // Do not break, since perhaps the other responders know.
        _ => panic!("OCSPCertStatus is an unknown value."),
    };
    Some(response)
}
