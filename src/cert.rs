use std::str;
use x509_parser;
use x509_parser::x509::X509Version;
use x509_parser::parse_x509_certificate;

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
            "validity({}, {:?}, {:?}).",
            hash,
            &self.inner.validity.not_before.timestamp(),
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
        let mut key_usage: bool = false;
        let mut extended_key_usage: bool = false;
        let mut subject_alternative_names: bool = false;
        let mut subject_key_identifier: bool = false;
        let mut certificate_policies: bool = false;

        let mut exts = self
            .inner
            .extensions
            .iter()
            .filter_map(|(oid, ext)| match oid.to_id_string().as_str() {
                "2.5.29.15" => { key_usage = true; Some(extensions::emit_key_usage(hash, &ext))},
                "2.5.29.37" => { extended_key_usage = true; Some(extensions::emit_extended_key_usage(hash, &ext)) },
                "2.5.29.17" => { subject_alternative_names = true; Some(extensions::emit_subject_alternative_names(hash, &ext)) },
                "2.5.29.14" => { subject_key_identifier = true; Some(extensions::emit_subject_key_identifier(hash, &ext)) },
                "2.5.29.32" => { certificate_policies = true; Some(extensions::emit_certificate_policies(hash, &ext)) },
                _ => None
            })
            .collect::<Vec<String>>();

        exts.push(self.emit_basic_constraints(hash));
        if !key_usage { exts.push(format!("extensionExists({}, \"KeyUsage\", false).", hash)) }
        if !extended_key_usage { exts.push(format!("extensionExists({}, \"ExtendedKeyUsage\", false).", hash)) }
        if !subject_alternative_names { exts.push(format!("extensionExists({}, \"SubjectAlternativeNames\", false).", hash)) }
        if !subject_key_identifier { exts.push(format!("extensionExists({}, \"SubjectKeyIdentifier\", false).", hash)) }
        if !certificate_policies { exts.push(format!("extensionExists({}, \"CertificatePolicies\", false).", hash)) }

        format!("{}\n", exts.join("\n"))
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

    pub fn emit_subject_public_key_algorithm(&self, hash: &String) -> String {
        let algorithm = self.inner.subject_pki.algorithm.algorithm.to_string();
        format!("keyAlgorithm({}, {:?}).", hash, algorithm)
    }
}

