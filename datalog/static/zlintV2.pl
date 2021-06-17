:- use_module(std).
:- use_module(certs).

%includes zlint tests made into prolog rules

%All CA Cert: keyUsage ext must be present and marked critical (21,35)
%checked CA certs for keyUsage extension and that it is marked critical
caKeyUsagePresent(Cert) :-
	certs:isCA(Cert),
	certs:keyUsageExt(Certs, true),
	certs:keyUsageCritical(Certs, true).

%caKeyUsagePresent(Cert) :-
%	\+certs:isCA(Cert).

%cert policies must be present and not marked critical (39)
%checkes subCA for certificate policies and if they are marked critical
subCaCertPoliciesNotMarkedCritical(Cert) :-
	certs:certificatePoliciesExt(Cert, true),
	certs:certificatePoliciesCritical(Cert, false).

%Root ca: basic constraint must appear as critical extension (18)
%Checks that root CA basic constraints are critical
basicConstraintsCritical(Cert) :-
	certs:isCA(Cert),
	std:isRoot(Cert),
	certs:basicConstraintsExt(Cert, true),
	certs:basicConstraintsCritical(Cert, true).

basicConstraintsCritical(Cert) :-
	\+certs:isCA(Cert),
	\+std:isRoot(Cert).

%Root CA: path length constraint field should not be present (20)
%Checks root CA for no length constraint
rootPathLenNotPresent(Cert) :-
	std:isRoot(Cert),
	certs:pathLimit(Cert, none).

rootPathLenNotPresent(Cert) :-
	\+std:isRoot(Cert).

%checks that root certificate extended key usage is not present (24)
rootExtKeyUseNotPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, false).

%rules are tested here
verified(Cert) :-
	std:isCert(Cert),
	rootExtKeyUseNotPresent(Cert).
	%caKeyUsagePresent(Cert).
	%rootPathLenNotPresent(Cert).

	%basicConstraintsCritical(Cert).
	%certs:isCA(Cert).
	%subCaCertPoliciesNotMarkedCritical(Cert).

	
	%nameConstraintEmpty(Cert).

	%certs:san(Cert, Name),
	%certs:isCA(Cert, Boolean),
	%std:stringMatch("*.google.com", "www.google.com").
	%ext:s_endswith(Name, ".com").
