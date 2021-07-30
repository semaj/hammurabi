:- use_module(std).
:- use_module(certs).
:- use_module(env).
:- use_module(ext).
%:- use_module(public_suffix_list).

% includes zlint tests made into prolog rules

% Helper methods up here
% checks if cert is a root certificate
rootApplies(Cert) :-
	%certs:isCA(Cert, true),
	%std:isRoot(Cert).
	certs:fingerprint(Cert, Fingerprint),
    trusted_roots(Fingerprint).

isSubCA(Cert) :-
	certs:isCA(Cert, true),
	\+std:isRoot(Cert).

% check for if it is a subscriber certificate
isSubCert(Cert) :-
	certs:isCA(Cert, false).

 
%  Root CA and Subordinate CA Certificate: 
%  keyUsage extension MUST be present and MUST be marked critical.
caKeyUsageCriticalApplies(Cert) :-
	certs:isCA(Cert, true).

caKeyUsageCritical(Cert) :-
	\+caKeyUsageCriticalApplies(Cert).

caKeyUsageCritical(Cert) :-
	certs:keyUsageExt(Cert, true),
	certs:keyUsageCritical(Cert, true).


%  Subordinate CA Certificate: certificatePolicies 
%  MUST be present and SHOULD NOT be marked critical.
subCaCertPoliciesExtPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, true).

subCaCertPoliciesExtPresent(Cert) :-
	\+isSubCA(Cert).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	certs:certificatePoliciesCritical(Cert, false).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	\+isSubCA(Cert).


%  Root CA Certificate: basicConstraints MUST appear as a critical extension
rootBasicConstraintsCritical(Cert) :-
	certs:basicConstraintsExt(Cert, true),
	certs:basicConstraintsCritical(Cert, true).

rootBasicConstraintsCritical(Cert) :-
	\+rootApplies(Cert).


%  Root CA Certificate: The pathLenConstraintField SHOULD NOT be present.
% Checks root CA for no length constraint
rootPathLenNotPresent(Cert) :-
	certs:pathLimit(Cert, none).

rootPathLenNotPresent(Cert) :-
	\+rootApplies(Cert).


%  Root CA Certificate: extendedKeyUsage MUST NOT be present.
rootExtKeyUseNotPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, false).

rootExtKeyUseNotPresent(Cert) :-
	\+rootApplies(Cert).


%  Root CA Certificate: certificatePolicies SHOULD NOT be present.
rootCertPoliciesNotPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, false).

rootCertPoliciesNotPresent(Cert) :-
	\+rootApplies(Cert).


%  Subscriber Certificate: extKeyUsage either the value id-kp-serverAuth
%  or id-kp-clientAuth or both values MUST be present.
%  Subscriber Certificate: extKeyUsage id-kp-emailProtection MAY be present.
%  Other values SHOULD NOT be present.
%  Subscriber Certificate: extKeyUsage: Any other values SHOULD NOT be present.

% ExtendedKeyUsage extensions allowed
allowed_EKU(serverAuth).
allowed_EKU(clientAuth).
allowed_EKU(emailProtection).

% helper function: checks for not allowed EKU
subCertEkuValuesNotAllowed(Cert) :-
	certs:extendedKeyUsage(Cert, Value),
	\+allowed_EKU(Value).

% subscriber cert: Extended key usage values allowed
subCertEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth),
	\+subCertEkuValuesNotAllowed(Cert).

subCertEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, clientAuth),
	\+subCertEkuValuesNotAllowed(Cert).

subCertEkuValidFields(Cert) :-
	\+isSubCert(Cert).


%  Subordinate CA: Must include an EKU extension.
subCaEkuPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, true).

subCaEkuPresent(Cert) :-
	\+isSubCA(Cert).


%  Subordinate CA Certificate: extkeyUsage, either id-kp-serverAuth
%  or id-kp-clientAuth or both values MUST be present.
subCaEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, serverAuth).

subCaEkuValidFields(Cert) :-
	certs:extendedKeyUsage(Cert, clientAuth).

subCaEkuValidFields(Cert) :-
	\+isSubCA(Cert).


%  Subscriber Certificate: certificatePolicies MUST be present
%  and SHOULD NOT be marked critical.
subCertCertPoliciesExtPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, true).

subCertCertPoliciesExtPresent(Cert) :-
	\+isSubCert(Cert).

subCertCertPoliciesNotMarkedCritical(Cert) :-
	certs:certificatePoliciesCritical(Cert, false).

subCertCertPoliciesNotMarkedCritical(Cert) :-
	\+isSubCert(Cert).


%  Subordinate CA Certificate: NameConstraints if present,
%  SHOULD be marked critical.

% if subCA has name constraints it must be marked critical
subCaNameConstCritApplies(Cert) :-
	isSubCA(Cert),
	certs:nameConstraintsExt(Cert, true).

subCaNameConstrainsCritical(Cert) :-
	certs:nameConstraintsCritical(Cert, true).

subCaNameConstrainsCritical(Cert) :-
	\+subCaNameConstCritApplies(Cert).


%  Root CA: SHOULD NOT contain the certificatePolicies extension.
rootCertPoliciesExtNotPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, false).

rootCertPoliciesExtNotPresent(Cert) :-
	\+rootApplies(Cert).


%  Subscriber Certificate: commonName is deprecated.
%  common name is deprecated if anything other than ""

% sub cert: common name is deprecated if anything other than ""
% Look at later
subCertCommonNameNotIncluded(Cert) :-
	certs:commonName(Cert, "").

subCertCommonNameNotIncluded(Cert) :-
	\+isSubCert(Cert).


%  Subscriber Certificate: commonName If present,
%  the field MUST contain a single IP address or FQDN that 
%  is one of the values contained in the subjAltName extension.
subCertCommonNameFromSanApplies(Cert) :-
	isSubCert(Cert),
	\+certs:commonName(Cert, "").

subCertCommonNameFromSan(Cert) :-
	certs:commonName(Cert, CN),
	certs:san(Cert, SN),
	string_lower(CN, CNL),
	string_lower(SN, SNL),
	equal(CNL, SNL).

subCertCommonNameFromSan(Cert) :-
	\+subCertCommonNameFromSanApplies(Cert).


%  Subordinate CA Certificate: cRLDistributionPoints MUST be present 
%  and MUST NOT be marked critical.
subCaCrlDistributionPointsPresent(Cert) :-
	certs:CRLDistributionPointsExt(Cert, true),
	\+certs:CRLDistributionPoints(Cert, false).

subCaCrlDistributionPointsPresent(Cert) :-
	\+isSubCA(Cert).

subCaCrlDistPointsNotMarkedCritical(Cert) :-
	certs:CRLDistributionPointsCritical(Cert, false).

subCaCrlDistPointsNotMarkedCritical(Cert) :-
	\+isSubCA(Cert).


%  Subordinate CA Certificate: cRLDistributionPoints MUST contain
%  the HTTP URL of the CAs CRL service.
subCaCrlDistPointContainsHttpUrl(Cert) :-
	certs:CRLDistributionPoint(Cert, Url),
	s_startswith(Url, "http://").

% another scenario for if there are ldap points before the http
subCaCrlDistPointContainsHttpUrl(Cert) :-
	certs:CRLDistributionPoint(Cert, Url),
	substring("http://", Url).
	%s_occurrences(Url, "http://", N),
	%equal(N, 1).

subCaCrlDistPointContainsHttpUrl(Cert) :-
	\+isSubCA(Cert).

%  Subscriber Certifcate: cRLDistributionPoints MAY be present.
% not considered in valid scope - might delete this one
subCertCrlDistributionPointsPresent(Cert) :-
	certs:CRLDistributionPointsExt(Cert, true),
	\+certs:CRLDistributionPoints(Cert, false).

subCertCrlDistributionPointsPresent(Cert) :-
	\+isSubCert(Cert).

%  Subscriber Certifcate: cRLDistributionPoints MUST NOT be marked critical,
%  and MUST contain the HTTP URL of the CAs CRL service.
subCertCrlDistPointsNotMarkedCritical(Cert) :-
	certs:CRLDistributionPointsCritical(Cert, false).

subCertCrlDistPointsNotMarkedCritical(Cert) :-
	certs:CRLDistributionPoint(Cert, false).

subCertCrlDistPointsNotMarkedCritical(Cert) :-
	\+isSubCert(Cert).

% sub cert: cRLDistributionPoints MUST contain the HTTP URL of the CAs CRL service
subCertCrlDistPointContainsHttpUrl(Cert) :-
	certs:CRLDistributionPoint(Cert, Url),
	s_startswith(Url, "http://").

subCertCrlDistPointContainsHttpUrl(Cert) :-
	certs:CRLDistributionPoint(Cert, Url),
	s_occurrences(Url, "http://", N),
	equal(N, 1).

subCertCrlDistPointContainsHttpUrl(Cert) :-
	certs:CRLDistributionPoint(Cert, false).

subCertCrlDistPointContainsHttpUrl(Cert) :-
	\+isSubCert(Cert).

%  Subscriber Certificate: authorityInformationAccess MUST NOT be marked critical
subCertAIANotMarkedCritical(Cert) :-
	certs:authorityInfoAccessCritical(Cert, false).

subCertAIANotMarkedCritical(Cert) :-
	\+isSubCert(Cert).


%  Subscriber Certificate: authorityInformationAccess MUST contain the
%  HTTP URL of the Issuing CAs OSCP responder.
subCertAIAContainsOCSPUrl(Cert) :-
	certs:authorityInfoAccessLocation(Cert, "OCSP", Url),
	s_startswith(Url, "http://").

subCertAIAContainsOCSPUrl(Cert) :-
	\+isSubCert(Cert).


%  Subordinate CA Certificate: authorityInformationAccess MUST contain
%  the HTTP URL of the Issuing CAs OSCP responder.
subCAAIAContainsOCSPUrl(Cert) :-
	certs:authorityInfoAccessLocation(Cert, "OCSP", Url),
	s_startswith(Url, "http://").

subCAAIAContainsOCSPUrl(Cert) :-
	\+isSubCA(Cert).


%  Subordinate CA Certificate: authorityInformationAccess SHOULD
%  also contain the HTTP URL of the Issuing CAs certificate.
subCAAIAContainsIssuingCAUrl(Cert) :-
	certs:authorityInfoAccessLocation(Cert, "CA Issuers", Url),
	s_startswith(Url, "http://").

subCAAIAContainsIssuingCAUrl(Cert) :-
	\+isSubCA(Cert).

% check common name and subject alternate name
% Subordinate CA: If includes id-kp-serverAuth EKU,
% then it MUST include Name constraints w/ 
% constraints on DNSName, IPAddress, and DirectoryName
%subCAEkuNameConstraintsApplies(Cert) :-
%	certs:extendedKeyUsage(Cert, serverAuth).

%subCAEkuNameConstraints(Cert) :-
%	certs:nameConstraintsPermitted(Cert, "DNS", Constraint).

%subCAEkuNameConstraints(Cert) :-
%	\+subCAEkuNameConstraintsApplies(Cert).

%subCAEkuNameConstraints(Cert) :-
%	\+isSubCA(Cert).


%  the CA MUST establish and follow a documented procedure[^pubsuffix] that
%  determines if the wildcard character occurs in the first label position to
%  the left of a “registry‐controlled” label or “public suffix”
% look for * and then see what string is 
% cant have more than one, has to be at beginning, 
% has to be character and no more than first character, must not be public
% suffix right after it
% make fact list with all public suffixes in it and check against it
containsWildcard(Cert) :-
	certs:san(Cert, San),
	s_occurrences(San, '*', N),
	geq(N, 1).

dnsWildcardNotLeftOfPublicSuffix(Cert) :-
	certs:san(Cert, San),
	s_occurrences(San, '*', N),
	equal(N, 1),
	public_suffix(Pubsuff),
	s_endswith(San, Pubsuff),
	%prolog rule below
	string_length(Pubsuff, Length),
	sub_string(San, Before, After, Length, Extract),
	geq(After, 4),
	s_endswith(Extract, "."),
	s_startswith(Extract, "*.").

dnsWildcardNotLeftOfPublicSuffix(Cert) :-
	\+containsWildcard(Cert).


dnsWildcardNotLeftOfPublicSuffix(Cert) :-
	\+isSubCert(Cert).

% Rules are tested here
verified(Cert) :-
	std:isCert(Cert),
	dnsWildcardNotLeftOfPublicSuffix(Cert).
	%dnsWildcardNotLeftOfPublicSuffix(Cert).
	
	%subCertEkuValidFields(Cert).
	%subCAAIAContainsOCSPUrl(Cert).
	%subCAAIAContainsIssuingCAUrl(Cert).
	%subCertAIAContainsOCSPUrl(Cert).
	%subCertAIANotMarkedCritical(Cert).
	%subCaCrlDistPointContainsHttpUrl(Cert).
	%subCertCrlDistPointContainsHttpUrl(Cert).
	%subCertCrlDistPointsNotMarkedCritical(Cert).
	%subCertCrlDistributionPointsPresent(Cert).

	%subCaCrlDistPointsNotMarkedCritical(Cert).
	%subCertCommonNameFromSan(Cert).
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

% Trusted roots needed for testing
trusted_roots("4F39D3BB9E7FA7BFB290E9D21EBB7827D3D7F89394A3AE0F46F50D7583FFBC84").
trusted_roots("BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C").
trusted_roots("001BD98347D99058CD3D1CCE175922BF032FA33A5456B7B1625B5914D0C429FB").
trusted_roots("4CC434E240BBDF1900D4AD568B5EA48A1721CEE0397C7AE582CF6F2FFF11C711").
trusted_roots("BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C").
trusted_roots("52E36BE5D0E39B7A06DC26A9A5A5B6F7DA3F313BF62BD19D967615BFD58C81CC").

% Public suffixes for testing
public_suffix("zp.ua").
public_suffix("zt.ua").
public_suffix("ug").
public_suffix("co.ug").
public_suffix("or.ug").
public_suffix("ac.ug").
public_suffix("sc.ug").
public_suffix("go.ug").
public_suffix("ne.ug").
public_suffix("com.ug").
public_suffix("org.ug").
public_suffix("uk").
public_suffix("ac.uk").
public_suffix("co.uk").
public_suffix("gov.uk").
public_suffix("ltd.uk").
public_suffix("me.uk").
public_suffix("net.uk").
public_suffix("nhs.uk").
public_suffix("org.uk").
public_suffix("plc.uk").
public_suffix("police.uk").
public_suffix("sch.uk").
public_suffix("us").


% Converts lua rules into prolog rules
% I need to make s_occurrences
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

substring(X,S) :-
  append(_,T,S) ,
  append(X,_,T) ,
  X \= [].

count([],_,0).
count([X|T],X,Y):- count(T,X,Z), Y is 1+Z.
count([_|T],X,Z):- count(T,X,Z).

s_occurrences(Str, Chr, Num) :-
    string_chars(Str, Lst),
    count(Lst, Chr, Num).
