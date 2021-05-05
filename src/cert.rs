use std::str;
use hex;
use x509_parser;
use x509_parser::x509::X509Version;
use x509_parser::parse_x509_certificate;
use x509_parser::extensions::GeneralName;
use std::net::Ipv4Addr;

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
            "{}\n\n",
            vec![
                self.emit_serial(&hash),
                self.emit_validity(&hash),
                self.emit_subject(&hash),
                self.emit_issuer(&hash),
                self.emit_version(&hash),
                self.emit_sign_alg(&hash),
                self.emit_subject_public_key_algorithm(&hash),
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

    fn name_from_rdn(name: &x509_parser::x509::X509Name) -> String {
        let mut cn: String = String::from("");
        let mut cnt_n: String = String::from("");
        let mut ln: String = String::from("");
        let mut spn: String = String::from("");
        let mut on: String = String::from("");
        &name.rdn_seq.iter().for_each(|f| {
            //println!("{:?}", f.set);
            // TODO: This should PROBABLY be a foldLeft() equivilant instead of a foreach()
            match f.set[0].attr_type.to_string().as_str() {
                "2.5.4.3" => {
                    cn = PrologCert::str_from_rdn(f)
                }
                "2.5.4.6" => {
                    cnt_n = PrologCert::str_from_rdn(f)
                }
                "2.5.4.7" => {
                    ln = PrologCert::str_from_rdn(f)
                }
                "2.5.4.8" => {
                    spn = PrologCert::str_from_rdn(f)
                }
                "2.5.4.10" => {
                    on = PrologCert::str_from_rdn(f)
                }
                _ => (),
            }
        });
        format!("\"{}\", \"{}\", \"{}\", \"{}\", \"{}\"", cn, cnt_n, ln, spn, on)
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

    pub fn emit_subject(&self, hash: &String) -> String {
        format!(
            "subject({}, {}).",
            hash,
            PrologCert::name_from_rdn(&self.inner.subject).to_lowercase()
        )
    }

    pub fn emit_serial(&self, hash: &String) -> String {
        format!("serialNumber({}, \"{}\").", hash, self.serial)
    }

    pub fn emit_issuer(&self, hash: &String) -> String {
        format!(
            "issuer({}, {}).",
            hash,
            PrologCert::name_from_rdn(&self.inner.issuer).to_lowercase()
        )
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

        let mut exts = self
            .inner
            .extensions
            .iter()
            .filter_map(|(oid, ext)| match oid.to_id_string().as_str() {
                "2.5.29.14" => { subject_key_identifier = true; Some(extensions::emit_subject_key_identifier(hash, &ext)) },
                "2.5.29.32" => { certificate_policies = true; Some(extensions::emit_certificate_policies(hash, &ext)) },
                _ => None
            })
            .collect::<Vec<String>>();

        exts.push(self.emit_key_usage(hash));
        exts.push(self.emit_basic_constraints(hash));
        exts.push(self.emit_extended_key_usage(hash));
        exts.push(self.emit_subject_alternative_names(hash));
        if !subject_key_identifier { exts.push(format!("extensionExists({}, \"SubjectKeyIdentifier\", false).", hash)) }
        if !certificate_policies { exts.push(format!("extensionExists({}, \"CertificatePolicies\", false).", hash)) }
        exts.push(self.emit_name_constraints(hash));
        exts.push(self.emit_policy_extras(hash));

        format!("{}\n", exts.join("\n"))
    }

    pub fn emit_name_constraints(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.name_constraints() {
            Some((is_critical, constraints)) => {
                answer.push(format!("extensionExists({}, \"NameConstraints\", true).", hash));
                answer.push(format!("exensionCritic({}, \"NameConstraints\", {}).", hash, is_critical));
                for permitted in constraints.permitted_subtrees.as_ref().unwrap_or(&vec![]) {
                    let (title, name) = emit_general_name(&permitted.base);
                    answer.push(format!("extensionValues({}, \"NameConstraints\", \"Permitted\", \"{}\", \"{}\").", hash, title, name));
                }
                for excluded in constraints.excluded_subtrees.as_ref().unwrap_or(&vec![]) {
                    let (title, name) = emit_general_name(&excluded.base);
                    answer.push(format!("extensionValues({}, \"NameConstraints\", \"Excluded\", \"{}\", \"{}\").", hash, title, name));
                }
            },
            None => {
                answer.push(format!("extensionExists({}, \"NameConstraints\", false).",
                hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_subject_alternative_names(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.subject_alternative_name() {
            Some((is_critical, sans)) => {
                answer.push(format!("extensionExists({}, \"SubjectAlternativeNames\", true).", hash));
                answer.push(format!("exensionCritic({}, \"SubjectAlternativeNames\", {}).", hash, is_critical));
                for general_name in &sans.general_names {
                    let (_, name) = emit_general_name(general_name);
                    answer.push(format!("extensionValues({}, \"SubjectAlternativeNames\", \"{}\").",
                    hash, name));
                }
            },
            None => {
                answer.push(format!("extensionExists({}, \"SubjectAlternativeNames\", false).",
                hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_policy_extras(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.policy_constraints() {
            Some((is_critical, policies)) => {
                answer.push(format!("extensionExists({}, \"PolicyConstraints\", true).", hash));
                answer.push(format!("exensionCritic({}, \"PolicyConstraints\", {}).", hash, is_critical));
                match policies.require_explicit_policy {
                    Some(u) => {
                    answer.push(format!("extensionValues({}, \"PolicyConstraints\", \"RequireExplicitPolicy\", {}).", hash, u));
                    },
                    None => {
                    answer.push(format!("extensionValues({}, \"PolicyConstraints\", \"RequireExplicitPolicy\", none).", hash));
                    }
                }
                match policies.inhibit_policy_mapping {
                    Some(u) => {
                    answer.push(format!("extensionValues({}, \"PolicyConstraints\", \"InhibitPolicyMapping\", {}).", hash, u));
                    },
                    None => {
                    answer.push(format!("extensionValues({}, \"PolicyConstraints\", \"InhibitPolicyMapping\", none).", hash));
                    }
                }
            },
            None => {
                answer.push(format!("extensionExists({}, \"PolicyConstraints\", false).", hash))
            }
        }
        match self.inner.inhibit_anypolicy() {
            Some((is_critical, policies)) => {
                answer.push(format!("extensionExists({}, \"InhibitAnyPolicy\", true).", hash));
                answer.push(format!("exensionCritic({}, \"InhibitAnyPolicy\", {}).", hash, is_critical));
                answer.push(format!("extensionValues({}, \"InhibitAnyPolicy\", {}).", hash, policies.skip_certs));
            },
            None => {
                answer.push(format!("extensionExists({}, \"InhibitAnyPolicy\", false).", hash))
            }
        }
        match self.inner.policy_mappings() {
            Some((is_critical, policies)) => {
                answer.push(format!("extensionExists({}, \"PolicyMappings\", true).", hash));
                answer.push(format!("exensionCritic({}, \"PolicyMappings\", {}).", hash, is_critical));
                for (oid, value_oids) in &policies.mappings {
                    for value_oid in value_oids {
                        answer.push(format!("exensionCritic({}, \"PolicyMappings\", \"{}\", \"{}\").", hash, oid.to_id_string(), value_oid.to_id_string()));
                    }
                }
            },
            None => {
                answer.push(format!("extensionExists({}, \"PolicyMappings\", false).", hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_basic_constraints(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.basic_constraints() {
            Some((is_critical, basic_constraints)) => {
            answer.push(format!("extensionExists({}, \"BasicConstraints\", true).", hash));
            answer.push(format!("exensionCritic({}, \"BasicConstraints\", {}).", hash, is_critical));
            let path_constraint: String = basic_constraints.path_len_constraint.map_or(
                "none".to_string(),
                |x| x.to_string()
            );
            answer.push(format!("extensionValues({}, \"BasicConstraints\", {}, {}).",
                    hash,
                    basic_constraints.ca,
                    path_constraint));
            },
            None => {
                answer.push(format!("extensionExists({}, \"BasicConstraints\", false).", hash))
            }
        }
        return answer.join("\n");
    }

    pub fn emit_key_usage(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.key_usage() {
            Some((is_critical, key_usage)) => {
                answer.push(format!("extensionExists({}, \"KeyUsage\", true).", hash));
                answer.push(format!("exensionCritic({}, \"KeyUsage\", {}).", hash, is_critical));
                let prefix: String = format!("extensionValues({}, \"KeyUsage\",", hash);
                answer.push(format!("{} \"digitalSignature\", {:?}).",
                        prefix, key_usage.digital_signature()));
                answer.push(format!("{} \"nonRepudiation\", {:?}).",
                        prefix, key_usage.non_repudiation()));
                answer.push(format!("{} \"keyEncipherment\", {:?}).",
                        prefix, key_usage.key_encipherment()));
                answer.push(format!("{} \"dataEncipherment\", {:?}).",
                        prefix, key_usage.data_encipherment()));
                answer.push(format!("{} \"keyAgreement\", {:?}).",
                        prefix, key_usage.key_agreement()));
                answer.push(format!("{} \"keyCertSign\", {:?}).",
                        prefix, key_usage.key_cert_sign()));
                answer.push(format!("{} \"cRLSign\", {:?}).",
                        prefix, key_usage.crl_sign()));
                answer.push(format!("{} \"encipherOnly\", {:?}).",
                        prefix, key_usage.encipher_only()));
                answer.push(format!("{} \"decipherOnly\", {:?}).",
                        prefix, key_usage.decipher_only()));
            }
            None => answer.push(format!("extensionExists({}, \"KeyUsage\", false).", hash))
        }
        return answer.join("\n");
    }

    pub fn emit_extended_key_usage(&self, hash: &String) -> String {
        let mut answer: Vec<String> = Vec::new();
        match self.inner.extended_key_usage() {
            Some((is_critical, eku)) => {
                answer.push(format!("extensionExists({}, \"ExtendedKeyUsage\", true).", hash));
                answer.push(format!("exensionCritic({}, \"ExtendedKeyUsage\", {}).", hash, is_critical));
                let prefix: String = format!("extensionValues({}, \"ExtendedKeyUsage\",", hash);
                answer.push(format!("{} \"serverAuth\", {:?}).", prefix, eku.server_auth));
                answer.push(format!("{} \"clientAuth\", {:?}).", prefix, eku.client_auth));
                answer.push(format!("{} \"codeSigning\", {:?}).", prefix, eku.code_signing));
                answer.push(format!("{} \"emailProtection\", {:?}).", prefix, eku.email_protection));
                answer.push(format!("{} \"timeStamping\", {:?}).", prefix, eku.time_stamping));
                answer.push(format!("{} \"OCSPSigning\", {:?}).", prefix, eku.ocscp_signing));
                // TODO: Use this in Datalog
                answer.push(format!("{} \"any\", {:?}).", prefix, eku.any));
                answer.push(format!("{} \"hasOther\", {:?}).", prefix, eku.other.len() > 0));
            }
            None => answer.push(format!("extensionExists({}, \"ExtendedKeyUsage\", false).", hash))
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

