use std::str;
use hex;
use x509_parser;
use x509_parser::x509::X509Version;
use x509_parser::parse_x509_certificate;
use x509_parser::extensions::GeneralName;
use std::net::Ipv4Addr;
use std::fs;
// use der_parser::{
//     ber::BerObjectContent,
//     der::{parse_der_integer, DerObject},
//     error::BerError,
//     *,
// };
// use nom::{combinator, IResult};
// use rsa::{BigUint, RSAPublicKey};

use simple_asn1::{ASN1Block, BigUint};
use std::fmt;
use std::fmt::{Display, Formatter};
mod extensions;

#[derive(Debug)]
pub struct PrologCert<'a> {
    inner: x509_parser::certificate::TbsCertificate<'a>,
    pub serial: String,
}

impl PrologCert<'_> {
    pub fn from_der(cert_der: &'_ [u8]) -> Result<PrologCert, ()> {
        match parse_x509_certificate(cert_der) {
            Ok((rem, parsed)) => {
                assert!(rem.is_empty());
                Ok(PrologCert {
                    serial: format!("{}", parsed.tbs_certificate.serial),
                    inner: parsed.tbs_certificate,
                })
            }
            Err(e) => {
                eprintln!("X509Parser error: {}", e);
                return Err(());
            }
        }
    }

    pub fn emit_all(&self, hash: &String) -> String {
        format!(
            "{}",
            vec![
                self.emit_serial(&hash),
                self.emit_validity(&hash),
                self.emit_common_name(&hash),
                self.emit_country(&hash),
                self.emit_organization(&hash),
                self.emit_given_name(&hash), 
                self.emit_surname(&hash),
                self.emit_state_or_prov(&hash), 
                self.emit_locality(&hash),
                self.emit_postal_code(&hash),
                // self.emit_subject(&hash),
                self.emit_version(&hash),
                self.emit_sign_alg(&hash),
                self.emit_subject_public_key_algorithm(&hash),
                self.emit_rsa_pub_key(&hash),
                self.emit_key_len(&hash),
                self.emit_extensions(&hash),
            ]
            .join("\n")
        )
    }

    fn str_from_rdn(name: &x509_parser::x509::RelativeDistinguishedName) -> String {
        String::from(
            str::from_utf8(
                name.set[0].attr_value.content.as_slice().
                unwrap()
            ).unwrap(),
        ).replace("\"", "\\\"")
    }

    // fn name_from_rdn(name: &x509_parser::x509::X509Name) -> String {
    //     let mut cn: String = String::from("");
    //     let mut cnt_n: String = String::from("");
    //     let mut ln: String = String::from("");
    //     let mut spn: String = String::from("");
    //     let mut on: String = String::from("");
    //     &name.rdn_seq.iter().for_each(|f| {
    //         //println!("{:?}", f.set);
    //         // TODO: This should PROBABLY be a foldLeft() equivilant instead of a foreach()
    //         match f.set[0].attr_type.to_string().as_str() {
    //             "2.5.4.3" => {
    //                 cn = PrologCert::str_from_rdn(f)
    //             }
    //             "2.5.4.6" => {
    //                 cnt_n = PrologCert::str_from_rdn(f)
    //             }
    //             "2.5.4.7" => {
    //                 ln = PrologCert::str_from_rdn(f)
    //             }
    //             "2.5.4.8" => {
    //                 spn = PrologCert::str_from_rdn(f)
    //             }
    //             "2.5.4.10" => {
    //                 on = PrologCert::str_from_rdn(f)
    //             }
    //             _ => (),
    //         }
    //     });
    //     format!("\"{}\", \"{}\", \"{}\", \"{}\", \"{}\"", cn, cnt_n, ln, spn, on)
    // }

    fn emit_common_name(&self, hash: &String) -> String {
        let mut cn: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.3" => {
                    cn = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("commonName({}, \"{}\").", hash, cn)
    }

    fn emit_country(&self, hash: &String) -> String { 
        let mut country: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.6" => {
                    country = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("country({}, \"{}\").", hash, country)
    }
    fn emit_organization(&self, hash: &String) -> String { 
        let mut org: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.10" => {
                    org = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("organizationName({}, \"{}\").", hash, org)
    }
    fn emit_given_name(&self, hash: &String) -> String { 
        let mut given: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.42" => {
                    given = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("givenName({}, \"{}\").", hash, given)
    }
    fn emit_surname(&self, hash: &String) -> String { 
        let mut surname: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.4" => {
                    surname = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("surname({}, \"{}\").", hash, surname)
    }
    fn emit_state_or_prov(&self, hash: &String) -> String { 
        let mut loc: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.8" => {
                    loc = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("stateOrProvinceName({}, \"{}\").", hash, loc)
    }
    fn emit_locality(&self, hash: &String) -> String { 
        let mut loc: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.7" => {
                    loc = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("localityName({}, \"{}\").", hash, loc)
    }
    fn emit_postal_code(&self, hash: &String) -> String { 
        let mut code: String = String::from("");
        &self.inner.subject.rdn_seq.iter().for_each(|f| {
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.17" => {
                    code = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("postalCode({}, \"{}\").", hash, code)
    }

    pub fn emit_validity(&self, hash: &String) -> String {
        format!(
            "notBefore({}, {:?}).\nnotAfter({}, {:?}).",
            hash,
            &self.inner.validity.not_before.timestamp(),
            hash,
            &self.inner.validity.not_after.timestamp()
        )
    }

    // pub fn emit_subject(&self, hash: &String) -> String {
    //     format!(
    //         "subject({}, {}).",
    //         hash,
    //         PrologCert::name_from_rdn(&self.inner.subject).to_lowercase()
    //     )
    // }

    pub fn emit_serial(&self, hash: &String) -> String {
        format!("serialNumber({}, \"{}\").", hash, self.serial)
    }

    pub fn emit_version(&self, hash: &String) -> String {
        let version = match self.inner.version {
            X509Version::V1 => 0,
            X509Version::V2 => 1,
            X509Version::V3 => 2,
            _ => panic!("Invalid version"),
        };
        format!("version({}, {}).", hash, version)
    }

    pub fn emit_sign_alg(&self, hash: &String) -> String {
        return format!(
            "signatureAlgorithm({}, {:?}).",
            hash,
            &self.inner.signature.algorithm.to_string()
        );
    }
    pub fn emit_rsa_pub_key(&self, hash: &String) -> String { 
        if self.inner.subject_pki.algorithm.algorithm.to_id_string().eq("1.2.840.113549.1.1.1") {
           let bytes = &self.inner.subject_pki.subject_public_key.data;
           let (n, e) = public_key_from_der(&bytes).unwrap();
            return format!( 
                "rsaModulus({}, {:?}).\nrsaExponent({}, {:?}).", 
                    hash, 
                    BigUint::from_bytes_be(&n),
                    hash, 
                    BigUint::from_bytes_be(&e)
                );
        }
        return format!( 
            "rsaModulus({}, {:?}).\nrsaExponent({}, {:?}).", 
                hash, 
                "NA",
                hash, 
                "NA"
            );
         
    }

    pub fn emit_key_len(&self, hash: &String) -> String {
        return format!(
            "keyLen({}, {}).",
            hash,
            &self.inner.subject_pki.subject_public_key.data.len()
        );
    }

    pub fn emit_extensions(&self, hash: &String) -> String {
        let mut subject_key_identifier: bool = false;
        let mut certificate_policies: bool = false;
        let mut crl_distribution_points: bool = false;
        let mut acc_assertions: bool = false;

        let mut exts = self
            .inner
            .extensions
            .iter()
            .filter_map(|(oid, ext)|
                match oid.to_id_string().as_str() {
                "2.5.29.14" => { subject_key_identifier = true; Some(extensions::emit_subject_key_identifier(hash, &ext)) },
                "2.5.29.32" => { certificate_policies = true; Some(extensions::emit_certificate_policies(hash, &ext)) },
                "2.5.29.31" => { crl_distribution_points = true; Some(extensions::emit_crl_distribution_points(hash, &ext)) },
                "1.3.3.7" => {
                    fs::write("datalog/static/tmp.pl", extensions::emit_acc_assertions(hash, &ext)).unwrap();
                    acc_assertions = true;
                    None
                },
                _ => {
                    None
                }
            })
            .collect::<Vec<String>>();

        exts.push(self.emit_key_usage(hash));
        exts.push(self.emit_basic_constraints(hash));
        exts.push(self.emit_extended_key_usage(hash));
        exts.push(self.emit_subject_alternative_names(hash));
        if !subject_key_identifier { exts.push(format!("subjectKeyIdentifierExt({}, false).", hash)) }
        if !certificate_policies { exts.push(format!("certificatePoliciesExt({}, false).", hash)) }
        if !crl_distribution_points { exts.push(format!("CRLDistributionPoints({}, false).", hash)) }
        if !acc_assertions { exts.push(format!("assertionCarryingCertificateExt({}, false).", hash)) }
        exts.push(self.emit_name_constraints(hash));
        exts.push(self.emit_policy_extras(hash));


        format!("{}\n", exts.join("\n"))
    }

    pub fn emit_name_constraints(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.name_constraints() {
            Some((is_critical, constraints)) => {
                answer.push(format!("nameConstraintsExt({}, true).", hash));
                answer.push(format!("nameConstraintsCritical({}, {}).", hash, is_critical));
                for permitted in constraints.permitted_subtrees.as_ref().unwrap_or(&vec![]) {
                    let (title, name) = emit_general_name(&permitted.base);
                    answer.push(format!("nameConstraintsPermitted({}, \"{}\", \"{}\").", hash, title, name));
                }
                for excluded in constraints.excluded_subtrees.as_ref().unwrap_or(&vec![]) {
                    let (title, name) = emit_general_name(&excluded.base);
                    answer.push(format!("nameConstraintsExcluded({}, \"{}\", \"{}\").", hash, title, name));
                }
            },
            None => {
                answer.push(format!("nameConstraintsExt({}, false).", hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_subject_alternative_names(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.subject_alternative_name() {
            Some((is_critical, sans)) => {
                answer.push(format!("sanExt({}, true).", hash));
                answer.push(format!("sanCritical({}, {}).", hash, is_critical));
                for general_name in &sans.general_names {
                    let (_, name) = emit_general_name(general_name);
                    answer.push(format!("san({}, \"{}\").",
                    hash, name));
                }
            },
            None => {
                answer.push(format!("sanExt({}, false).", hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_policy_extras(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.policy_constraints() {
            Some((is_critical, policies)) => {
                answer.push(format!("policyConstraintsExt({}, true).", hash));
                answer.push(format!("policyConstraintsCritical({}, {}).", hash, is_critical));
                match policies.require_explicit_policy {
                    Some(u) => {
                    answer.push(format!("requireExplicitPolicy({}, {}).", hash, u));
                    },
                    None => {
                    answer.push(format!("requireExplicitPolicy({}, none).", hash));
                    }
                }
                match policies.inhibit_policy_mapping {
                    Some(u) => {
                    answer.push(format!("inhibitPolicyMapping({}, {}).", hash, u));
                    },
                    None => {
                    answer.push(format!("inhibitPolicyMapping({}, none).", hash));
                    }
                }
            },
            None => {
                answer.push(format!("policyConstraintsExt({}, false).", hash))
            }
        }
        match self.inner.inhibit_anypolicy() {
            Some((is_critical, policies)) => {
                answer.push(format!("inhibitAnyPolicyExt({}, true).", hash));
                answer.push(format!("inhibitAnyPolicyCritical({}, {}).", hash, is_critical));
                answer.push(format!("inhibitAnyPolicy({}, {}).", hash, policies.skip_certs));
            },
            None => {
                answer.push(format!("inhibitAnyPolicyExt({}, false).", hash))
            }
        }
        match self.inner.policy_mappings() {
            Some((is_critical, policies)) => {
                answer.push(format!("policyMappingsExt({}, true).", hash));
                answer.push(format!("policyMappingsCritial({}, {}).", hash, is_critical));
                for (oid, value_oids) in &policies.mappings {
                    for value_oid in value_oids {
                        answer.push(format!("policyMappings({}, \"{}\", \"{}\").", hash, oid.to_id_string(), value_oid.to_id_string()));
                    }
                }
            },
            None => {
                answer.push(format!("policyMappingsExt({}, \"PolicyMappings\", false).", hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_basic_constraints(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.basic_constraints() {
            Some((is_critical, basic_constraints)) => {
            answer.push(format!("basicConstraintsExt({}, true).", hash));
            answer.push(format!("basicConstraintsCritical({}, {}).", hash, is_critical));
            let path_constraint: String = basic_constraints.path_len_constraint.map_or(
                "none".to_string(),
                |x| x.to_string()
            );
            answer.push(format!("isCA({}, {}).", hash, basic_constraints.ca));
            answer.push(format!("pathLimit({}, {}).", hash, path_constraint));
            },
            None => {
                answer.push(format!("basicConstraintsExt({}, false).", hash));
            }
        }
        return answer.join("\n");
    }

    pub fn emit_key_usage(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.key_usage() {
            Some((is_critical, key_usage)) => {
                answer.push(format!("keyUsageExt({}, true).", hash));
                answer.push(format!("keyUsageCritical({}, {}).", hash, is_critical));
                let prefix: String = format!("keyUsage({},", hash);
                if key_usage.digital_signature() {
                    answer.push(format!("{} digitalSignature).", prefix));
                }
                if key_usage.non_repudiation() {
                    answer.push(format!("{} nonRepudiation).", prefix));
                }
                if key_usage.key_encipherment() {
                    answer.push(format!("{} keyEncipherment).", prefix));
                }
                if key_usage.data_encipherment() {
                    answer.push(format!("{} dataEncipherment).", prefix));
                }
                if key_usage.key_agreement() {
                    answer.push(format!("{} keyAgreement).", prefix));
                }
                if key_usage.key_cert_sign() {
                    answer.push(format!("{} keyCertSign).", prefix));
                }
                if key_usage.crl_sign() {
                    answer.push(format!("{} cRLSign).", prefix));
                }
                if key_usage.encipher_only() {
                    answer.push(format!("{} encipherOnly).", prefix));
                }
                if key_usage.decipher_only() {
                    answer.push(format!("{} decipherOnly).", prefix));
                }
            }
            None => answer.push(format!("keyUsageExt({}, false).", hash))
        }
        return answer.join("\n");
    }

    pub fn emit_extended_key_usage(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.extended_key_usage() {
            Some((is_critical, eku)) => {
                answer.push(format!("extendedKeyUsageExt({}, true).", hash));
                answer.push(format!("extendedKeyUsageCritical({}, {}).", hash, is_critical));
                let prefix: String = format!("extendedKeyUsage({},", hash);
                if eku.server_auth {
                answer.push(format!("{} serverAuth).", prefix));
                }
                if eku.client_auth {
                    answer.push(format!("{} clientAuth).", prefix));
                }
                if eku.code_signing {
                    answer.push(format!("{} codeSigning).", prefix));
                }
                if eku.email_protection {
                    answer.push(format!("{} emailProtection).", prefix));
                }
                if eku.time_stamping {
                    answer.push(format!("{} timeStamping).", prefix));
                }
                if eku.ocscp_signing {
                    answer.push(format!("{} oCSPSigning).", prefix));
                }
                    // TODO: Use this in Datalog
                if eku.any {
                    answer.push(format!("{} any).", prefix));
                }
                if eku.other.len() > 0 {
                    answer.push(format!("{} hasOther).", prefix));
                }
            }
            None => answer.push(format!("extendedKeyUsageExt({}, false).", hash))
        }
        return answer.join("\n");
    }


    pub fn emit_subject_public_key_algorithm(&self, hash: &String) -> String {
        let algorithm = self.inner.subject_pki.algorithm.algorithm.to_string();
        format!("keyAlgorithm({}, {:?}).", hash, algorithm)
    }
}

fn emit_general_name(name: &GeneralName) -> (String, String) {
    match name {
        GeneralName::OtherName(_, bytes) => {
            ("Other".to_string(), str::from_utf8(bytes).map_or(hex::encode(bytes), |x| x.to_string()))
        },
        GeneralName::RFC822Name(s) => ("RFC822".to_string(), s.to_string()),
        GeneralName::DNSName(s) => ("DNS".to_string(), s.to_string()),
        GeneralName::DirectoryName(x509_name) => {
            ("Directory".to_string(), hex::encode(x509_name.as_raw()))
        },
        GeneralName::URI(s) => ("URI".to_string(), s.to_string()),
        GeneralName::IPAddress(bytes) => {
            if bytes.len() == 8 { // ip+netmask
                let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                ("IPv4Address".to_string(), format!("{}", ip))
            } else {
                ("IPv6Address".to_string(), "unsupported".to_string())
            }
        },
        GeneralName::RegisteredID(oid) => ("OID".to_string(), oid.to_string()),
    }
}


/* The following code was taken from https://github.com/caelunshun/rsa-der
    but modified slightly to work with BitStringObjects as returned by the parser */
    
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Indicates that a DER decoding error occurred.
    InvalidDer(simple_asn1::ASN1DecodeErr),
    /// Indicates that the RSA ASN.1 sequence was not found.
    SequenceNotFound,
    /// Indicates that the RSA modulus value was not found.
    ModulusNotFound,
    /// Indicates that the RSA exponent value was not found.
    ExponentNotFound,
    /// Indicates that the RSA ASN.1 sequence did not contain exactly two values (one
    /// for `n` and one for `e`).
    InvalidSequenceLength,
}

type StdResult<T, E> = std::result::Result<T, E>;

/// Result type for `rsa-der`. This type
/// is equivalent to `std::result::Result<T, rsa_der::Error>`.
pub type RsaResult<T> = StdResult<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> StdResult<(), fmt::Error> {
        match self {
            Error::InvalidDer(e) => e.fmt(f)?,
            Error::SequenceNotFound => f.write_str("ASN.1 sequence not found")?,
            Error::ModulusNotFound => f.write_str("ASN.1 public key modulus not found")?,
            Error::ExponentNotFound => f.write_str("ASN.1 public key exponent not found")?,
            Error::InvalidSequenceLength => {
                f.write_str("ASN.1 sequence did not contain exactly two values")?
            }
        }

        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InvalidDer(e) => Some(e),
            _ => None,
        }
    }
}
pub fn public_key_from_der(bit_string: &[u8]) -> RsaResult<(Vec<u8>, Vec<u8>)> {

    let inner_asn = simple_asn1::from_der(bit_string).map_err(Error::InvalidDer)?;

    let (n, e) = match &inner_asn[0] {
        ASN1Block::Sequence(_, blocks) => {
            if blocks.len() != 2 {
                return Err(Error::InvalidSequenceLength);
            }

            let n = match &blocks[0] {
                ASN1Block::Integer(_, n) => n,
                _ => return Err(Error::ModulusNotFound),
            };

            let e = match &blocks[1] {
                ASN1Block::Integer(_, e) => e,
                _ => return Err(Error::ExponentNotFound),
            };

            (n, e)
        }
        _ => return Err(Error::SequenceNotFound),
    };

    Ok((n.to_bytes_be().1, e.to_bytes_be().1))
}