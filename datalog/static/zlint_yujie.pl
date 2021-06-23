:- use_module(certs).
:- use_module(std).
:- use_module(env).
:- use_module(ext).


% sub_ca_cert: ca field MUST be set to true.
caIsCa(Cert) :-
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
  certs:certificatePoliciesExt(Cert, true).
 
 
% ca_cert: organizationName MUST appear.
caOrganizationNameMissing(Cert) :-
  caIsCa(Cert),
  organizationNameIsPresent(Cert).


/* 
  sub_cert: stateOrProvinceName MUST appeear if 
  organizationName, givenName, or surname are present 
  and localityName is absent.
*/
subCertProvinceMustAppear(Cert) :-

  
/***** helper methods *****/
givenNameIsPresent(Cert) :-
  certs:givenName(Cert, Given),
  \+ext:equal(Given, "").

surnameIsPresent(Cert) :- 
  certs:surname(Cert, Surname),
  \+ext:equal(Surname, "").
  
organizationNameIsPresent(Cert) :-
  certs:organizationName(Cert, Org),
  \+ext:equal(Org, "").
  
stateOrProvinceNameIsPresent(Cert) :-
  certs:stateOrProvinceName(Cert, Sop),
  \+ext:equal(Sop, "").

localityNameIsPresent(Cert) :-
  certs:localityName(Cert, Loc),
  \+ext:equal(Loc, "").
