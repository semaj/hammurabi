:- module(ev, [
    anyPolicyOid/1,
    evPolicyOid/6
]).

% The anyPolicy OID, usable by intermediates
anyPolicyOid("2.5.29.32.0").

% all recognized EV policy OIDs
% maps ev policy OIDs to root cert subject info
% evPolicyOid(Oid, CN, C, L, ST, O).
% Replace subject with serial number here
evPolicyOid("1.3.6.1.4.1.6334.1.100.1", "Cybertrust Global Root","","","","Cybertrust, Inc").
evPolicyOid("2.16.756.1.89.1.2.1.1", "SwissSign Gold CA - G2","CH","","","SwissSign AG").
evPolicyOid("2.16.840.1.114404.1.1.2.4.1", "XRamp Global Certification Authority","US","","","XRamp Security Services Inc").
evPolicyOid("2.16.840.1.114404.1.1.2.4.1", "SecureTrust CA","US","","","SecureTrust Corporation").
evPolicyOid("2.16.840.1.114404.1.1.2.4.1", "Secure Global CA","US","","","SecureTrust Corporation").
evPolicyOid("1.3.6.1.4.1.6449.1.2.1.5.1", "COMODO ECC Certification Authority","GB","Salford","Greater Manchester","COMODO CA Limited").
evPolicyOid("1.3.6.1.4.1.6449.1.2.1.5.1", "COMODO Certification Authority","GB","Salford","Greater Manchester","COMODO CA Limited").
evPolicyOid("2.16.840.1.114413.1.7.23.3", "","US","","","\"The Go Daddy Group, Inc.\""). % no matching root cert
evPolicyOid("2.16.840.1.114413.1.7.23.3", "Go Daddy Root Certificate Authority - G2","US","Scottsdale","Arizona","GoDaddy.com, Inc."). % no matching root cert
evPolicyOid("2.16.840.1.114414.1.7.23.3", "","US","","","\"Starfield Technologies, Inc.\""). % no matching root cert
evPolicyOid("2.16.840.1.114414.1.7.23.3", "Starfield Root Certificate Authority - G2","US","Scottsdale","Arizona","Starfield Technologies, Inc"). % no matching root cert
evPolicyOid("2.16.840.1.114412.2.1", "DigiCert High Assurance EV Root CA","US","","","DigiCert Inc").
evPolicyOid("1.3.6.1.4.1.8024.0.2.100.1.2", "QuoVadis Root CA 2","BM","","","QuoVadis Limited").
evPolicyOid("1.3.6.1.4.1.782.1.2.1.8.1", "Network Solutions Certificate Authority","US","","","Network Solutions L.L.C.").
evPolicyOid("2.16.840.1.114028.10.1.2", "Entrust Root Certification Authority","US","","","Entrust, Inc.").
evPolicyOid("2.16.840.1.114028.10.1.2", "Entrust Root Certification Authority - G4","US","","","Entrust, Inc.").
evPolicyOid("2.23.140.1.1", "GlobalSign Root CA","BE","","","GlobalSign nv-sa").
evPolicyOid("2.23.140.1.1", "GlobalSign","","","","GlobalSign"). % multiple matching root certs
evPolicyOid("2.16.578.1.26.1.3.3", "Buypass Class 3 Root CA","NO","","","Buypass AS-983163327").
evPolicyOid("1.3.6.1.4.1.17326.10.14.2.1.2", "Chambers of Commerce Root - 2008","EU","Madrid (see current address at www.camerfirma.com/address)","","AC Camerfirma S.A.").
evPolicyOid("1.3.6.1.4.1.34697.2.1", "AffirmTrust Commercial","US","","","AffirmTrust").
evPolicyOid("1.3.6.1.4.1.34697.2.2", "AffirmTrust Networking","US","","","AffirmTrust").
evPolicyOid("1.3.6.1.4.1.34697.2.3", "AffirmTrust Premium","US","","","AffirmTrust").
evPolicyOid("1.3.6.1.4.1.34697.2.4", "AffirmTrust Premium ECC","US","","","AffirmTrust").
evPolicyOid("1.2.616.1.113527.2.5.1.1", "Certum Trusted Network CA","PL","","","Unizeto Technologies S.A.").
evPolicyOid("1.2.616.1.113527.2.5.1.1", "Certum Trusted Network CA 2","PL","","","Unizeto Technologies S.A.").
evPolicyOid("1.3.6.1.4.1.14777.6.1.1", "Izenpe.com","ES","","","IZENPE S.A.").
evPolicyOid("1.3.6.1.4.1.14777.6.1.2", "Izenpe.com","ES","","","IZENPE S.A.").
evPolicyOid("1.3.6.1.4.1.7879.13.24.1", "T-TeleSec GlobalRoot Class 3","DE","","","T-Systems Enterprise Services GmbH").
evPolicyOid("1.3.6.1.4.1.40869.1.1.22.3", "TWCA Root Certification Authority","TW","","","TAIWAN-CA").
evPolicyOid("1.3.6.1.4.1.4788.2.202.1", "D-TRUST Root Class 3 CA 2 EV 2009","DE","","","D-Trust GmbH").
evPolicyOid("1.3.6.1.4.1.13177.10.1.3.10", "Autoridad de Certificacion Firmaprofesional CIF A62634068","ES","","","").
evPolicyOid("1.3.6.1.4.1.40869.1.1.22.3", "TWCA Global Root CA","TW","","","TAIWAN-CA").
evPolicyOid("2.16.792.3.0.4.1.1.4", "E-Tugra Certification Authority","TR","Ankara","","E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş.").
evPolicyOid("1.3.159.1.17.1", "Actalis Authentication Root CA","IT","Milan","","Actalis S.p.A./03358520967").
evPolicyOid("2.16.840.1.114412.2.1", "DigiCert Assured ID Root G2","US","","","DigiCert Inc").
evPolicyOid("2.16.840.1.114412.2.1", "DigiCert Assured ID Root G3","US","","","DigiCert Inc").
evPolicyOid("2.16.840.1.114412.2.1", "DigiCert Global Root G2","US","","","DigiCert Inc").
evPolicyOid("2.16.840.1.114412.2.1", "DigiCert Global Root G3","US","","","DigiCert Inc").
evPolicyOid("2.16.840.1.114412.2.1", "DigiCert Trusted Root G4","US","","","DigiCert Inc").
evPolicyOid("1.3.6.1.4.1.8024.0.2.100.1.2", "QuoVadis Root CA 2 G3","BM","","","QuoVadis Limited").
evPolicyOid("1.3.6.1.4.1.6449.1.2.1.5.1", "COMODO RSA Certification Authority","GB","Salford","Greater Manchester","COMODO CA Limited").
evPolicyOid("1.3.6.1.4.1.6449.1.2.1.5.1", "USERTrust RSA Certification Authority","US","Jersey City","New Jersey","The USERTRUST Network").
evPolicyOid("1.3.6.1.4.1.6449.1.2.1.5.1", "USERTrust ECC Certification Authority","US","Jersey City","New Jersey","The USERTRUST Network").
evPolicyOid("2.16.840.1.114028.10.1.2", "Entrust.net Certification Authority (2048)","","","","Entrust.net").
evPolicyOid("2.16.528.1.1003.1.2.7", "Staat der Nederlanden EV Root CA","NL","","","Staat der Nederlanden").
evPolicyOid("2.16.840.1.114028.10.1.2", "Entrust Root Certification Authority - G2","US","","","Entrust, Inc.").
evPolicyOid("2.16.840.1.114028.10.1.2", "Entrust Root Certification Authority - EC1","US","","","Entrust, Inc.").
evPolicyOid("2.16.156.112554.3", "CFCA EV ROOT","CN","","","China Financial Certification Authority").
evPolicyOid("1.2.392.200091.100.721.1", "","JP","","","SECOM Trust Systems CO.,LTD."). % no matching root cert
evPolicyOid("2.16.756.5.14.7.4.8", "OISTE WISeKey Global Root GB CA","CH","","","WISeKey").
evPolicyOid("2.23.140.1.1", "Amazon Root CA 1","US","","","Amazon").
evPolicyOid("2.23.140.1.1", "Amazon Root CA 2","US","","","Amazon").
evPolicyOid("2.23.140.1.1", "Amazon Root CA 3","US","","","Amazon").
evPolicyOid("2.23.140.1.1", "Amazon Root CA 4","US","","","Amazon").
evPolicyOid("2.23.140.1.1", "Starfield Services Root Certificate Authority - G2","US","Scottsdale","Arizona","Starfield Technologies, Inc."). % no matching root cert
evPolicyOid("1.2.156.112559.1.1.6.1", "GDCA TrustAUTH R5 ROOT","CN","","","GUANG DONG CERTIFICATE AUTHORITY CO.,LTD.").
evPolicyOid("2.23.140.1.1", "SSL.com EV Root Certification Authority ECC","US","Houston","Texas","SSL Corporation").
evPolicyOid("2.23.140.1.1", "SSL.com EV Root Certification Authority RSA R2","US","Houston","Texas","SSL Corporation").
evPolicyOid("2.23.140.1.1", "UCA Extended Validation Root","CN","","","UniTrust").
evPolicyOid("2.23.140.1.1", "Hongkong Post Root CA 3","HK","Hong Kong","Hong Kong","Hongkong Post").
evPolicyOid("2.23.140.1.1", "emSign Root CA - G1","IN","","","eMudhra Technologies Limited").
evPolicyOid("2.23.140.1.1", "emSign ECC Root CA - G3","IN","","","eMudhra Technologies Limited").
evPolicyOid("2.23.140.1.1", "emSign Root CA - C1","US","","","eMudhra Inc").
evPolicyOid("2.23.140.1.1", "emSign ECC Root CA - C3","US","","","eMudhra Inc").
