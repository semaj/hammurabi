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
  
subCertGivenOrSurnameHasCorrectPolicy(Cert) :- 
  certs:givenName(Cert, Given),
  \+ext:equal(Given, ""),
  certs:certificatePolicies(Cert, Oid),
  ext:equal(Oid, "2.23.140.1.2.3").

subCertGivenOrSurnameHasCorrectPolicy(Cert) :-
  certs:surname(Cert, Surname),
  \+ext:equal(Surname, ""),
  certs:certificatePolicies(Cert, Oid),
  ext:equal(Oid, "2.23.140.1.2.3").
