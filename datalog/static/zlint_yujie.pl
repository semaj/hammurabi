:- use_module(certs).
:- use_module(std).
:- use_module(env).
:- use_module(ext).


% sub_ca_cert: ca field MUST be set to true.
subCaIsCa(Cert) :-
  certs:isCA(Cert, true).

% root_ca_cert: ca field MUST be set to true.
rootCaIsCa(Cert) :-
  certs:isCA(Cert, true).
  
% sub_ca_cert: basicConstraints MUST be present & marked critical.
basicConstaintsMustBeCritical(Cert) :-
  certs:basicConstraintsExt(Cert, true),
  certs:basicConstraintsCritical(Cert, true).


/* 
  sub_cert: A cert containing givenName or surname 
  MUST contain the (2.23.140.1.2.3) certPolicy OID.
*/
subCertGivenOrSurnameHasCorrectPolicy(Cert) :- 
  givenNameIsPresent(Cert),
  certs:certificatePolicies(Cert, Oid),
  ext:equal(Oid, "2.23.140.1.2.3").

subCertGivenOrSurnameHasCorrectPolicy(Cert) :-
  surnameIsPresent(Cert),
  certs:certificatePolicies(Cert, Oid),
  ext:equal(Oid, "2.23.140.1.2.3").


/* 
  sub_cert: 
  localityName MUST appear if organizationName, givenName, 
  or surname are present but stateOrProvinceName is absent.
*/
subCertLocalityNameMustAppear(Cert) :-
  organizationNameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert).
  
subCertLocalityNameMustAppear(Cert) :-
  givenNameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert).

subCertLocalityNameMustAppear(Cert) :-
  surnameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert).
  
  
% sub_cert: MUST contain one or more policy identifiers.
subCertCertPolicyEmpty(Cert) :- 
  certs:certificatePoliciesExt(Cert, false).
 
 
% ca_cert: organizationName MUST appear.
caOrganizationNameMissing(Cert) :-
  caIsCa(Cert),
  \+organizationNameIsPresent(Cert).


/* 
  sub_cert: stateOrProvinceName MUST appeear if 
  organizationName, givenName, or surname are present 
  and localityName is absent.
*/
subCertProvinceMustAppear(Cert) :-
  organizationNameIsPresent(Cert),
  \+localityNameIsPresent(Cert).

subCertProvinceMustAppear(Cert) :-
  givenNameIsPresent(Cert),
  \+localityNameIsPresent(Cert).

subCertProvinceMustAppear(Cert) :-
  surnameIsPresent(Cert),
  \+localityNameIsPresent(Cert).


/* 
  sub_cert: stateOrProvinceName MUST NOT appeear if 
  organizationName, givenName, or surname are absent.
*/
subCertProvinceMustNotAppear(Cert) :-
  \+organizationNameIsPresent(Cert).
  
subCertProvinceMustNotAppear(Cert) :-
  \+givenNameIsPresent(Cert).
 
subCertProvinceMustNotAppear(Cert) :-
  \+surnameIsPresent(Cert).


% Any of the following x509.SignatureAlgorithms are acceptable per BRs §6.1.5

sha1_sig_algo("1.2.840.113549.1.1.5"). % sha-1WithRSAEncryption
sha1_sig_algo("1.2.840.10040.4.3"). % id-dsa-with-sha1
sha1_sig_algo("1.2.840.10045.4.1"). % ecdsa-with-sha1

sha256_sig_algo("1.2.840.113549.1.1.11"). % sha-256WithRSAEncryption
sha256_sig_algo("2.16.840.1.101.3.4.3.2"). % id-dsa-with-sha256
sha256_sig_algo("1.2.840.10045.4.3.2"). % ecdsa-with-sha256

sha384_sig_algo("1.2.840.113549.1.1.12"). % sha-384WithRSAEncryption
sha384_sig_algo("1.2.840.10045.4.3.3"). % ecdsa-with-sha384

sha512_sig_algo("1.2.840.113549.1.1.13"). % sha-512WithRSAEncryption
sha512_sig_algo("1.2.840.10045.4.3.4"). % ecdsa-with-sha512


/*
  Certificates MUST meet the following algorithm requirements: 
  SHA-1*, SHA-256, SHA-384, SHA-512
*/
signatureAlgorithmNotSupported(Cert) :-
  certs:signatureAlgorithm(Cert, Algo),
  \+sha1_sig_algo(Algo),
  \+sha256_sig_algo(Algo),
  \+sha384_sig_algo(Algo),
  \+sha512_sig_algo(Algo).


% Certificates MUST be of type X.509 v3.
invalidCertificateVersion(Cert) :-
  certs:version(Cert, Ver),
  ext:unequal(Ver, 2).
  



anyPolicyOid("2.5.29.32.0").



/***** helper methods *****/
givenNameIsPresent(Cert) :-
  certs:givenName(Cert, Given),
  ext:unequal(Given, "").

surnameIsPresent(Cert) :- 
  certs:surname(Cert, Surname),
  ext:unequal(Surname, "").
  
organizationNameIsPresent(Cert) :-
  certs:organizationName(Cert, Org),
  ext:unequal(Org, "").
  
stateOrProvinceNameIsPresent(Cert) :-
  certs:stateOrProvinceName(Cert, Sop),
  ext:unequal(Sop, "").

localityNameIsPresent(Cert) :-
  certs:localityName(Cert, Loc),
  ext:unequal(Loc, "").
