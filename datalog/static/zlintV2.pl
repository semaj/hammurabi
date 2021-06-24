:- use_module(std).
:- use_module(certs).
:- use_module(env).
:- use_module(ext).

%includes zlint tests made into prolog rules

%checks if caKeyUsageCritical rule is applicable
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
%checks subCA for certificate policies and that they are marked not critical
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
subCertEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, Value),
	\+allowed_EKU(Value).

%subscriber cert: Extended key usage values allowed
subCertEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth),
	\+subCertEkuValuesNotAllowed(Cert).

subCertEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, clientAuth),
	\+subCertEkuValuesNotAllowed(Cert).

subCertEkuValidFields(Cert) :-
	\+isSubCert(Cert).

%sub CA must include EKU extension
subCaEkuPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, true).

subCaEkuPresent(Cert) :-
	\+isSubCA(Cert).

%Subordinate CA: EKU either serverAuth, clientAuth, or both MUST be present
subCaEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth).

subCaEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, clientAuth).

subCaEkuValidFields(Cert) :-
	\+isSubCA(Cert).

%checks sub cert for certificate policies and that they are marked not critical
subCertCertPoliciesExtPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, true).

subCertCertPoliciesExtPresent(Cert) :-
	\+isSubCert(Cert).

subCertCertPoliciesNotMarkedCritical(Cert) :-
	certs:certificatePoliciesCritical(Cert, false).

subCertCertPoliciesNotMarkedCritical(Cert) :-
	\+isSubCert(Cert).


%if subCA has name constraints it must be marked critical
subCaNameConstCritApplies(Cert) :-
	isSubCA(Cert),
	certs:nameConstraintsExt(Cert, true).

subCaNameConstrainsCritical(Cert) :-
	certs:nameConstraintsCritical(Cert, true).

subCaNameConstrainsCritical(Cert) :-
	\+subCaNameConstCritApplies(Cert).

%root CA should not contain the certificatePolicies extension
rootCertPoliciesExtNotPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, false).

rootCertPoliciesExtNotPresent(Cert) :-
	\+rootApplies(Cert).

%sub cert: common name is deprecated if anything other than ""
%Look at later
subCertCommonNameNotIncluded(Cert) :-
	certs:commonName(Cert, "").

subCertCommonNameNotIncluded(Cert) :-
	\+isSubCert(Cert).
	
%sub cert: if CommonName present must contain a single IP address or FQDN part of subjAltName
subCertCommonNameFromSanApplies(Cert) :-
	isSubCert(Cert),
	\+certs:commonName(Cert, "").

subCertCommonNameFromSan(Cert) :-
	certs:commonName(Cert, CN),
	certs:san(Cert, SN),
	ext:to_lower(CN, CNL),
	ext:to_lower(SN, SNL),
	ext:equal(CNL, SNL).

%subCertCommonNameFromSan(Cert) :-
	%certs:commonName(Cert, CN).
	%add ip check

subCertCommonNameFromSan(Cert) :-
	\+subCertCommonNameFromSanApplies(Cert).


%rules are tested here
verified(Cert) :-
	std:isCert(Cert),
	subCertCommonNameFromSan(Cert).
	
	%rootCertPoliciesExtNotPresent(Cert).
	%subCaNameConstrainsCritical(Cert).
	%subCertCertPoliciesExtPresent(Cert).
	%subCertCertPoliciesNotMarkedCritical(Cert).
	%subCaEkuValidFields(Cert).
	%subCaEkuPresent(Cert).
	%subCertEkuValidFields(Cert).
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