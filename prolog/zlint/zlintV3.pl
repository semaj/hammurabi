%:- use_module(certs).
%:- use_module(std).
%:- use_module(env).
%:- use_module(ext).
:- include(prolog/gen/job/certs).
%:- include(prolog/gen/job/std).
%:- include(prolog/gen/env).
	
isSubCA(Cert) :-
	certs:isCA(Cert, true),
	\+std:isRoot(Cert).
  
isSubCert(Cert) :-
  certs:isCA(Cert, false).


caIsCaApplies(Cert) :-
	certs:keyUsageExt(Cert, true),
	certs:keyUsage(Cert, keyCertSign),
  	certs:basicConstraintsExt(Cert, true).
	
% sub_ca: ca field MUST be set to true.
subCaIsCa(Cert) :-
  isSubCA(Cert).

% root_ca: ca field MUST be set to true.
rootCaIsCa(Cert) :-
  certs:isCA(Cert, true),
  std:isRoot(Cert).
  
  
% sub_ca_cert: basicConstraints MUST be present & marked critical.
subCaBasicConstaintsMustBeCritical(Cert) :-
  certs:basicConstraintsExt(Cert, true),
  certs:basicConstraintsCritical(Cert, true).

subCaBasicConstaintsMustBeCritical(Cert) :-
  \+isSubCA(Cert).
 
% sub_cert: A cert containing givenName or surname 
% MUST contain the (2.23.140.1.2.3) certPolicy OID.
subCertGivenOrSurnameApplies(Cert) :-
  isSubCert(Cert),
  givenNameIsPresent(Cert).

subCertGivenOrSurnameApplies(Cert) :-
  isSubCert(Cert),
  surnameIsPresent(Cert).

subCertGivenOrSurnameHasCorrectPolicy(Cert) :- 
  certs:certificatePolicies(Cert, Oid),
  equal(Oid, "2.23.140.1.2.3").

subCertGivenOrSurnameHasCorrectPolicy(Cert) :-
  isSubCert(Cert),
  \+givenNameIsPresent(Cert),
  \+surnameIsPresent(Cert).

subCertGivenOrSurnameHasCorrectPolicy(Cert) :-
  \+isSubCert(Cert).

 
% sub_cert: 
% localityName MUST appear if organizationName, givenName, 
% or surname are present but stateOrProvinceName is absent.

subCertLocalityNameMustAppear(Cert) :-
  organizationNameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert),
  localityNameIsPresent(Cert).
  
subCertLocalityNameMustAppear(Cert) :-
  givenNameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert),
  localityNameIsPresent(Cert).

subCertLocalityNameMustAppear(Cert) :-
  surnameIsPresent(Cert),
  \+stateOrProvinceNameIsPresent(Cert),
  localityNameIsPresent(Cert).

subCertLocalityNameMustAppear(Cert) :-
  stateOrProvinceNameIsPresent(Cert).

subCertLocalityNameMustAppear(Cert) :-
  \+isSubCert(Cert).
  
  
% sub_cert: MUST contain one or more policy identifiers.
subCertContainsCertPolicy(Cert) :- 
  certs:certificatePoliciesExt(Cert, true),
  certs:certificatePolicies(Cert, _).

subCertContainsCertPolicy(Cert) :- 
  \+isSubCert(Cert).
 
% ca_cert: organizationName MUST appear.
isCA(Cert) :-
  certs:isCA(Cert, true).
  
caOrganizationNamePresent(Cert) :-
  organizationNameIsPresent(Cert).

% sub_cert: stateOrProvinceName MUST appear if
% organizationName, givenName, or surname are present 
% and localityName is absent.

subCertProvinceMustAppear(Cert) :-
  organizationNameIsPresent(Cert),
  \+localityNameIsPresent(Cert),
  \+certs:stateOrProvinceName(Cert, "").

subCertProvinceMustAppear(Cert) :-
  givenNameIsPresent(Cert),
  \+localityNameIsPresent(Cert),
  \+certs:stateOrProvinceName(Cert, "").

subCertProvinceMustAppear(Cert) :-
  surnameIsPresent(Cert),
  \+localityNameIsPresent(Cert),
  \+certs:stateOrProvinceName(Cert, "").

subCertProvinceMustAppear(Cert) :-
  \+organizationNameIsPresent(Cert),
  \+givenNameIsPresent(Cert),
  \+surnameIsPresent(Cert).

subCertProvinceMustAppear(Cert) :-
  \+isSubCert(Cert).

% sub_cert: stateOrProvinceName MUST NOT appeear if 
% organizationName, givenName, or surname are absent.
subCertProvinceMustNotAppear(Cert) :-
  \+organizationNameIsPresent(Cert),
  certs:stateOrProvinceName(cert_0, "").
  
subCertProvinceMustNotAppear(Cert) :-
  \+givenNameIsPresent(Cert),
  certs:stateOrProvinceName(cert_0, "").
 
subCertProvinceMustNotAppear(Cert) :-
  \+surnameIsPresent(Cert),
  certs:stateOrProvinceName(cert_0, "").

subCertProvinceMustNotAppear(Cert) :-
  organizationNameIsPresent(Cert),
  givenNameIsPresent(Cert),
  surnameIsPresent(Cert).

subCertProvinceMustNotAppear(Cert) :-
  \+isSubCert(Cert).


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


% Certificates MUST meet the following algorithm requirements: 
% SHA-1*, SHA-256, SHA-384, SHA-512
signatureAlgorithmSupported(Cert) :-
  certs:signatureAlgorithm(Cert, Algo),
  val_sig_algo(Algo).


% Certificates MUST meet the following requirements for DSA algorithm 
% type and key size: L=2048 and N=224,256 or L=3072 and N=256
dsaApplies(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, G).
  
dsaProperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, G),
  equal(L, 2048),
  equal(N, 224).

dsaProperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, G),
  equal(L, 2048),
  equal(N, 256).

dsaProperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, G),
  equal(L, 3072),
  equal(N, 256).

dsaProperModulusOrDivisorSize(Cert) :-
  \+certs:spkiDSAParameters(Cert, L, N, G).
  

% Certificates MUST include all domain parameters
dsaParamsAllPresent(Cert) :-
  certs:spkiDSAParameters(Cert, P, Q, G),
  unequal(P, 0),
  unequal(Q, 0),
  unequal(G, 0).

 
% Certificates MUST meet the following requirements for algorithm 
% type and key size: ECC NIST P-256(65), P-384(97), or P-521(133)
idecPKeyAlgo(Cert) :-
  certs:keyAlgorithm(Cert, Algo),
  equal(Algo, "1.2.840.10045.2.1").
  
ecProperCurves(Cert) :-
  idecPKeyAlgo(Cert),
  certs:keyLen(Cert, Len),
  geq(Len, 65).


% Certificates MUST be of type X.509 v3.
validCertificateVersion(Cert) :-
  certs:version(Cert, Ver),
  equal(Ver, 2).


% sub_ca: MUST NOT contain the anyPolicy identifier
subCaMustNotContainAnyPolicy(Cert) :-
  certs:certificatePoliciesExt(Cert, true),
  certs:certificatePolicies(Cert, Oid),
  \+anyPolicyOid(Oid).

subCaMustNotContainAnyPolicy(Cert) :-
  \+isSubCA(Cert).

anyPolicyOid("2.5.29.32.0").


% sub_cert: subjAltName MUST contain at least one entry.
extSanContainsEntries(Cert) :-
  certs:sanExt(Cert, true),
  certs:san(Cert, _).

extSanContainsEntries(Cert) :-
  \+isSubCert(Cert).

% sub_cert: basicContrainsts cA field MUST NOT be true.
subCertIsNotCa(Cert) :- 
  certs:keyUsageExt(Cert, true),
  certs:keyUsage(Cert, keyCertSign),
  certs:basicConstraintsExt(Cert, true),
  certs:isCA(Cert, false).


% If the Certificate asserts the policy identifier of 2.23.140.1.2.1, 
% then it MUST NOT include organizationName, streetAddress, localityName,
% stateOrProvinceName, or postalCode in the Subject field.

cabDvConflictsApplies(Cert) :-
  certs:isCA(Cert, false),
  certs:certificatePolicies(Cert, Oid),
  equal(Oid, "2.23.140.1.2.1").
  
cabDvDoesNotConflictWithLocality(Cert) :- 
  cabDvConflictsApplies(Cert),
  \+localityNameIsPresent(Cert).

cabDvDoesNotConflictWithOrg(Cert) :- 
  cabDvConflictsApplies(Cert),
  \+organizationNameIsPresent(Cert).

cabDvDoesNotConflictWithPostal(Cert) :- 
  cabDvConflictsApplies(Cert),
  \+postalCodeIsPresent(Cert).

cabDvDoesNotConflictWithProvince(Cert) :- 
  cabDvConflictsApplies(Cert),
  \+stateOrProvinceNameIsPresent(Cert).

cabDvDoesNotConflictWithStreet(Cert) :- 
  cabDvConflictsApplies(Cert),
  \+streetAddressIsPresent(Cert).



% sub_cert: streetAddress MUST NOT appear if organizationName, 
% 	    givenName, and surname fields are absent.
subCertStreetAddressMustNotAppear(Cert) :-
  \+organizationNameIsPresent(Cert),
  \+givenNameIsPresent(Cert),
  \+surnameIsPresent(Cert),
  \+streetAddressIsPresent(Cert).
  
subCertStreetAddressMustNotAppear(Cert) :-
  \+isSubCert(Cert).

% sub_cert: localityName MUST NOT appear if organizationName, 
%	    givenName, and surname fields are absent.
subCertLocalityNameMustNotAppear(Cert) :-
  \+organizationNameIsPresent(Cert),
  \+givenNameIsPresent(Cert),
  \+surnameIsPresent(Cert),
  \+localityNameIsPresent(Cert).

subCertLocalityNameMustNotAppear(Cert) :-
  \+isSubCert(Cert).

% sub_ca: authorityInformationAccess MUST be present, 
%         with the exception of stapling.  
subCaAiaPresent(Cert) :-
  certs:authorityInfoAccessExt(Cert, true).

subCaAiaPresent(Cert) :-
  \+isSubCA(Cert).


% sub_cert: authorityInformationAccess MUST be present, 
% 	    with the exception of stapling.  
subCertAiaPresent(Cert) :-
  certs:authorityInfoAccessExt(Cert, true).

subCertAiaPresent(Cert) :-
  \+isSubCert(Cert).


% sub_ca: authorityInformationAccess MUST NOT be marked critical
subCaAiaNotMarkedCritical(Cert) :-
  certs:authorityInfoAccessExt(Cert, true),
  certs:authorityInfoAccessCritical(Cert, false).

subCaAiaNotMarkedCritical(Cert) :-
  \+isSubCA(Cert).

% sub_ca: MUST include one or more explicit policy identifiers that 
%         indicates the Subordinate CA’s adherence to and compliance 
%	  with these requirements
subCaCertificatePoliciesPresent(Cert) :-
  certs:certificatePoliciesExt(Cert, true).

subCaCertificatePoliciesPresent(Cert) :-
  \+isSubCA(Cert).

% sub_ca: Bit positions for keyCertSign and cRLSign MUST be set.
caKeyCertSignSet(Cert) :-
  certs:isCA(Cert, true),
  certs:keyUsageExt(Cert, true),
  certs:keyUsage(Cert, keyCertSign).

caKeyCertSignSet(Cert) :-
  \+isSubCA(Cert).

caCrlSignSet(Cert) :-
  certs:isCA(Cert, true),
  certs:keyUsageExt(Cert, true),
  certs:keyUsage(Cert, cRLSign).

caCrlSignSet(Cert) :-
  \+isSubCA(Cert).

% sub_cert: keyUsage if present, bit positions for keyCertSign and cRLSign MUST NOT be set.
subCertKeyUsageCertSignBitNotSet(Cert) :-
  isSubCert(Cert),
  certs:keyUsageExt(Cert, true),
  \+certs:keyUsage(Cert, keyCertSign).

subCertKeyUsageCrlSignBitNotSet(Cert) :-
  isSubCert(Cert),
  certs:keyUsageExt(Cert, true),
  \+certs:keyUsage(Cert, cRLSign).
  
subCertKeyUsageCrlSignBitNotSet(Cert) :-
  \+isSubCert(Cert).


% helper methods

unequal(X, Y):-
    X \== Y.

equal(X, Y):-
    X == Y.

larger(X, Y):-
    X > Y.

geq(X, Y):-
    X >= Y.

add(X, Y, Z):-
    X = Y + Z.

subtract(X, Y, Z):-
    X = Y - Z.

s_endswith(String, Suffix):-
    string_concat(_, Suffix, String).

s_startswith(String, Prefix):-
    string_concat(Prefix, _, String).
    
givenNameIsPresent(Cert) :-
  certs:givenName(Cert, Given),
  unequal(Given, "").

surnameIsPresent(Cert) :- 
  certs:surname(Cert, Surname),
  unequal(Surname, "").
  
organizationNameIsPresent(Cert) :-
  certs:organizationName(Cert, Org),
  unequal(Org, "").
  
stateOrProvinceNameIsPresent(Cert) :-
  certs:stateOrProvinceName(Cert, Sop),
  unequal(Sop, "").

localityNameIsPresent(Cert) :-
  certs:localityName(Cert, Loc),
  unequal(Loc, "").
  
streetAddressIsPresent(Cert) :-
  certs:streetAddress(Cert, Street),
  unequal(Street, "").
  
postalCodeIsPresent(Cert) :-
  certs:postalCode(Cert, Code),
  unequal(Code, "").
  
