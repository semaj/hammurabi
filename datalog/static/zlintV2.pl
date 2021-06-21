:- use_module(std).
:- use_module(certs).

%includes zlint tests made into prolog rules

%checks if rule is applicable
caKeyUsageCriticalApplies(Cert) :-
	certs:isCA(Cert, true).

%if not applicable pass
caKeyUsageCritical(Cert) :-
	\+caKeyUsageCriticalApplies(Cert).

%All CA Cert: keyUsage ext must be present and marked critical (21,35)
%checked CA certs for keyUsage extension and that it is marked critical
caKeyUsageCritical(Cert) :-
	certs:keyUsageExt(Cert, true),
	certs:keyUsageCritical(Cert, true).


%cert policies must be present and not marked critical (39)
%checkes subCA for certificate policies and if they are marked critical
isSubCA(Cert) :-
	certs:isCA(Cert, true),
	\+std:isRoot(Cert).

subCaCertPoliciesExtPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, true).

subCaCertPoliciesExtPresent(Cert) :-
	\+isSubCA(Cert).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	certs:certificatePoliciesCritical(Cert, false).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	\+isSubCA(Cert).

%checks if cert is a root certificate
%Need to fix this - only roots in env.pl trusted
rootApplies(Cert) :-
	%certs:isCA(Cert, true),
	std:isRoot(Cert).

%Root ca: basic constraint must appear as critical extension (18)
%Checks that root CA basic constraints are critical
rootBasicConstraintsCritical(Cert) :-
	certs:basicConstraintsExt(Cert, true),
	certs:basicConstraintsCritical(Cert, true).

rootBasicConstraintsCritical(Cert) :-
	\+rootApplies(Cert).


%Root CA: path length constraint field should not be present (20)
%Checks root CA for no length constraint
rootPathLenNotPresent(Cert) :-
	certs:pathLimit(Cert, none).

rootPathLenNotPresent(Cert) :-
	\+rootApplies(Cert).


%checks that root certificate extended key usage is not present (24)
rootExtKeyUseNotPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, false).

rootExtKeyUseNotPresent(Cert) :-
	\+rootApplies(Cert).


%Root Cert: Certificate Policies should not be present (23)
rootCertPoliciesNotPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, false).

rootCertPoliciesNotPresent(Cert) :-
	\+rootApplies(Cert).

%check for if it is a sub certificate
isSubCert(Cert) :-
	\+isCA(Cert).

%subscriber cert: Extended key usage values allowed
subCertEkuValuesAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth),
	certs:extendedKeyUsage(Cert, clientAuth).

subCertEkuValuesAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth).

subCertEkuValuesAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, clientAuth).

subCertEkuValuesAllowed(Cert) :-
	\+isSubCert(Cert).

%rules are tested here
verified(Cert) :-
	std:isCert(Cert),
	rootCertPoliciesNotPresent(Cert).

	%rootExtKeyUseNotPresent(Cert).
	%rootPathLenNotPresent(Cert).
	%rootBasicConstraintsCritical(Cert).

	%subCaCertPoliciesExtPresent(Cert),
	%subCaCertPoliciesNotMarkedCritical(Cert).
	%caKeyUsageCritical(Cert).

	%certs:isCA(Cert).
	

	%certs:san(Cert, Name),
	%certs:isCA(Cert, Boolean),
	%std:stringMatch("*.google.com", "www.google.com").
	%ext:s_endswith(Name, ".com").
