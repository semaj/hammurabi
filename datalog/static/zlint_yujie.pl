:- use_module(certs).
:- use_module(std).
:- use_module(env).
:- use_module(ext).


isSubCA(Cert) :-
	certs:isCA(Cert, true),
	\+std:isRoot(Cert).
  
isSubCert(Cert) :-
  certs:isCA(Cert, false).

% sub_ca: ca field MUST be set to true.
subCaIsCa(Cert) :-
  isSubCA(Cert).

% root_ca: ca field MUST be set to true.
rootCaIsCa(Cert) :-
  certs:isCA(Cert, true),
  std:isRoot(Cert).
  
% sub_ca_cert: basicConstraints MUST be present & marked critical.
basicConstaintsMustBeCritical(Cert) :-
  isSubCA(Cert),
  certs:basicConstraintsExt(Cert, true),
  certs:basicConstraintsCritical(Cert, true).


/* 
  sub_cert: A cert containing givenName or surname 
  MUST contain the (2.23.140.1.2.3) certPolicy OID.
*/
subCertGivenOrSurnameHasCorrectPolicy(Cert) :- 
  isSubCert(Cert),
  givenNameIsPresent(Cert),
  certs:certificatePolicies(Cert, Oid),
  ext:equal(Oid, "2.23.140.1.2.3").

subCertGivenOrSurnameHasCorrectPolicy(Cert) :-
  isSubCert(Cert),
  surnameIsPresent(Cert),
  certs:certificatePolicies(Cert, Oid),
  ext:equal(Oid, "2.23.140.1.2.3").


/* 
  sub_cert: 
  localityName MUST appear if organizationName, givenName, 
  or surname are present but stateOrProvinceName is absent.
*/
subCertLocalityNameMustAppear(Cert) :-
  isSubCert(Cert),
  organizationNameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert).
  
subCertLocalityNameMustAppear(Cert) :-
  isSubCert(Cert),
  givenNameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert).

subCertLocalityNameMustAppear(Cert) :-
  isSubCert(Cert),
  surnameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert).
  
  
% sub_cert: MUST contain one or more policy identifiers.
subCertCertPolicyEmpty(Cert) :- 
  isSubCert(Cert),
  certs:certificatePoliciesExt(Cert, false).
 
 
% ca_cert: organizationName MUST appear.
caOrganizationNameMissing(Cert) :-
  certs:isCA(Cert, true),
  \+organizationNameIsPresent(Cert).


/* 
  sub_cert: stateOrProvinceName MUST appeear if
  organizationName, givenName, or surname are present 
  and localityName is absent.
*/
subCertProvinceMustAppear(Cert) :-
  isSubCert(Cert),
  organizationNameIsPresent(Cert),
  \+localityNameIsPresent(Cert).

subCertProvinceMustAppear(Cert) :-
  isSubCert(Cert),
  givenNameIsPresent(Cert),
  \+localityNameIsPresent(Cert).

subCertProvinceMustAppear(Cert) :-
  isSubCert(Cert),
  surnameIsPresent(Cert),
  \+localityNameIsPresent(Cert).


/* 
  sub_cert: stateOrProvinceName MUST NOT appeear if 
  organizationName, givenName, or surname are absent.
*/
subCertProvinceMustNotAppear(Cert) :-
  isSubCert(Cert),
  \+organizationNameIsPresent(Cert).
  
subCertProvinceMustNotAppear(Cert) :-
  isSubCert(Cert),
  \+givenNameIsPresent(Cert).
 
subCertProvinceMustNotAppear(Cert) :-
  isSubCert(Cert),
  \+surnameIsPresent(Cert).


% Any of the following x509.SignatureAlgorithms are acceptable per BRs §6.1.5

% SHA-1*
val_sig_algo("1.2.840.113549.1.1.5"). % sha-1WithRSAEncryption
val_sig_algo("1.2.840.10040.4.3"). % id-dsa-with-sha1
val_sig_algo("1.2.840.10045.4.1"). % ecdsa-with-sha1

% SHA-256
val_sig_algo("1.2.840.113549.1.1.11"). % sha-256WithRSAEncryption
val_sig_algo("2.16.840.1.101.3.4.3.2"). % id-dsa-with-sha256
val_sig_algo("1.2.840.10045.4.3.2"). % ecdsa-with-sha256

% SHA-384
val_sig_algo("1.2.840.113549.1.1.12"). % sha-384WithRSAEncryption
val_sig_algo("1.2.840.10045.4.3.3"). % ecdsa-with-sha384

% SHA-512
val_sig_algo("1.2.840.113549.1.1.13"). % sha-512WithRSAEncryption
val_sig_algo("1.2.840.10045.4.3.4"). % ecdsa-with-sha512


/*
  Certificates MUST meet the following algorithm requirements: 
  SHA-1*, SHA-256, SHA-384, SHA-512
*/
signatureAlgorithmNotSupported(Cert) :-
  certs:signatureAlgorithm(Cert, Algo),
  \+val_sig_algo(Algo).


/* 
  Certificates MUST meet the following requirements for DSA algorithm 
  type and key size: L=2048 and N=224,256 or L=3072 and N=256
*/
dsaImproperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(cert_0, L, N),
  ext:equals(L, 2048),
  ext:equals(N, 224).

dsaImproperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(cert_0, L, N),
  ext:equals(L, 2048),
  ext:equals(N, 256).

dsaImproperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(cert_0, L, N),
  ext:equals(L, 3072),
  ext:equals(N, 256).

dsaImproperModulusOrDivisorSize(Cert) :-
  \+certs:spkiDSAParameters(cert_0, L, N).
  
  
/* 
  Certificates MUST meet the following requirements for algorithm 
  type and key size: ECC NIST P-256(65), P-384(97), or P-521(133)
*/
ecImproperCurves(Cert) :-
  \+ecProperCurves(Cert).

ecProperCurves(Cert) :-
  idecPKeyAlgo(Cert),
  certs:keyLen(Cert, Len),
  ext:geq(Len, 65).

idecPKeyAlgo(Cert) :-
  certs:keyAlgorithm(Cert, Algo),
  ext:equals(Algo, "1.2.840.10045.2.1").
  

% Certificates MUST be of type X.509 v3.
invalidCertificateVersion(Cert) :-
  certs:version(Cert, Ver),
  ext:unequal(Ver, 2).


% sub_ca: MUST NOT contain the anyPolicy identifier
subCaMustNotContainAnyPolicy(Cert) :-
  isSubCA(Cert),
  certs:certificatePoliciesExt(Cert, true),
  certs:certificatePolicies(Cert, Oid),
  \+anyPolicyOid(Oid).

anyPolicyOid("2.5.29.32.0").


% sub_cert: subjAltName MUST contain at least one entry.
extSanNoEntries(Cert) :-
  isSubCert(Cert),
  certs:sanExt(Cert, true),
  \+certs:san(Cert, Name).


% sub_cert: basicContrainsts cA field MUST NOT be true.
subCertIsNotCa(Cert) :- 
  certs:keyUsageExt(Cert, true),
  certs:keyUsage(Cert, keyCertSign),
  certs:basicConstraintsExt(Cert, true),
  certs:isCA(Cert, false).


/* 
  If the Certificate asserts the policy identifier of 2.23.140.1.2.1, 
  then it MUST NOT include organizationName, streetAddress, localityName,
  stateOrProvinceName, or postalCode in the Subject field.
*/
cabDvConflictsApplies(Cert) :-
  certs:isCA(Cert, false),
  certs:certificatePolicies(Cert, Oid),
  ext:equals(Oid, "2.23.140.1.2.1").
  
cabDvConflictsWithLocality(Cert) :- 
  cabDvConflictsApplies(Cert),
  localityNameIsPresent(Cert).

cabDvConflictsWithOrg(Cert) :- 
  cabDvConflictsApplies(Cert),
  organizationNameIsPresent(Cert).

cabDvConflictsWithPostal(Cert) :- 
  cabDvConflictsApplies(Cert),
  postalCodeIsPresent(Cert).

cabDvConflictsWithProvince(Cert) :- 
  cabDvConflictsApplies(Cert),
  stateOrProvinceNameIsPresent(Cert).

cabDvConflictsWithStreet(Cert) :- 
  cabDvConflictsApplies(Cert),
  streetAddressIsPresent(Cert).
 

% sub_ca: authorityInformationAccess MUST be present, 
%         with the exception of stapling.  
subCaAiaMissing(Cert) :-
  isSubCA(Cert).
  



% sub_ca: authorityInformationAccess MUST NOT be marked critical
subCaAiaMarkedCritical(Cert) :-
  isSubCA(Cert),
  certs:authorityInfoAccessExt(Cert, true),
  \+certs:authorityInfoAccessCritical(Cert, false).



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
  
streetAddressIsPresent(Cert) :-
  certs:streetAddress(Cert, Street),
  ext:unequal(Street, "").
  
postalCodeIsPresent(Cert) :-
  certs:postalCode(Cert, Code),
  ext:unequal(Code, "").
  
