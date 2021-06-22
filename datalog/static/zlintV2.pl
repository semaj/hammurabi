:- use_module(std).
:- use_module(certs).
:- use_module(env).

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
%start adding at 3591
rootApplies(Cert) :-
	%certs:isCA(Cert, true),
	%std:isRoot(Cert).
	certs:fingerprint(Cert, Fingerprint),
    trusted_roots(Fingerprint).

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

%ExtendedKeyUsage extensions allowed
allowed_EKU(serverAuth).
allowed_EKU(clientAuth).
allowed_EKU(emailProtection).

%helper function: checks for not allowed EKU
subCertEkuValuesNotAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, Value),
	\+allowed_EKU(Value).

%subscriber cert: Extended key usage values allowed
subCertEkuValuesAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth),
	\+subCertEkuValuesNotAllowed(Cert).

subCertEkuValuesAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, clientAuth),
	\+subCertEkuValuesNotAllowed(Cert).

subCertEkuValuesAllowed(Cert) :-
	\+isSubCert(Cert).

%sub CA must include EKU extension
%lint_sub_ca_eku_missing_test.go
subCaEkuPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, true).

subCaEkuPresent(Cert) :-
	\+isSubCA(Cert).

%rules are tested here
verified(Cert) :-
	std:isCert(Cert),
	subCertEkuValuesAllowed(Cert).

	%subCaCertPoliciesExtPresent(Cert),
	%subCaCertPoliciesNotMarkedCritical(Cert).
	%rootCertPoliciesNotPresent(Cert).
	%rootExtKeyUseNotPresent(Cert).
	%rootPathLenNotPresent(Cert).
	%std:isRoot(Cert).
	%rootBasicConstraintsCritical(Cert).
	%caKeyUsageCritical(Cert).

	%certs:isCA(Cert).
	

	%certs:san(Cert, Name),
	%certs:isCA(Cert, Boolean),
	%std:stringMatch("*.google.com", "www.google.com").
	%ext:s_endswith(Name, ".com").

%trusted roots needed for testing
trusted_roots("4F39D3BB9E7FA7BFB290E9D21EBB7827D3D7F89394A3AE0F46F50D7583FFBC84").
trusted_roots("BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C").
trusted_roots("001BD98347D99058CD3D1CCE175922BF032FA33A5456B7B1625B5914D0C429FB").
trusted_roots("4CC434E240BBDF1900D4AD568B5EA48A1721CEE0397C7AE582CF6F2FFF11C711").
trusted_roots("BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C").
trusted_roots("52E36BE5D0E39B7A06DC26A9A5A5B6F7DA3F313BF62BD19D967615BFD58C81CC").