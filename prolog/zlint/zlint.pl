% Master zlint file - has all the lints in it
:- use_module("prolog/job/certs").
:- include(const).
:- discontiguous val_sig_algo/1.
% The following functions are taken from zlint
% specifically the cabf_br tests  
% but reimplemented using Prolog 
% See www.github.com/zmap/zlint for more information 

isCert(Cert) :-
  \+certs:serialNumber(Cert, "").

% Checks whether or not the common 
% name is missing
caCommonNameMissing(Cert) :- 
    certs:commonName(Cert, "").

% Checks whether the country name 
% is invalid
caCountryNameValidApplies(Cert) :-
  isCa(Cert), 
  caCountryNamePresent(Cert). 

caCountryNameValid(Cert) :- 
  certs:country(Cert, Country), 
  val_country(Country).

% Checks whether or not country name 
% is missing 
caCountryNameMissing(Cert) :- 
    certs:country(Cert, "").

caCountryNamePresent(Cert) :- 
  \+caCountryNameMissing(Cert).

% countryName must not appear if 
% the organizationName, givenName, 
% and surname are absent
countryNameMustNotAppearApplies(Cert) :- 
  givenNameMissing(Cert), 
  surnameMissing(Cert),
  caCountryNameMissing(Cert).

countryNameMustNotAppear(Cert) :- 
  caCountryNameMissing(Cert).

% Country Name must appear if 
% organizationName, givenName 
% Or surname is present 
%countryNameMustAppearApplies(Cert) :- 
%  \+organizationNameMissing(Cert).

%countryNameMustAppearApplies(Cert) :- 
%  \+givenNameMissing(Cert).

%countryNameMustAppearApplies(Cert) :- 
%  \+surnameMissing(Cert).

countryNameMustAppear(Cert) :- 
  \+caCountryNameMissing(Cert).

countryNameMustAppear(Cert) :- 
  organizationNameMissing(Cert), 
  givenNameMissing(Cert), 
  surnameMissing(Cert).

% If certificate asserts policy identifier 
% 2.23.140.1.2.3 then it must include either 
% (1) either organizationName, givenName, or surname
% (2) localityName
% (3) stateOrProvinceName
% (4) countryName

certPolicyIvApplies(Cert) :- 
  certs:certificatePolicies(Cert,  "2.23.140.1.2.3").

certPolicyIvRequiresOrgGivenOrSurname(Cert) :- 
  \+organizationNameMissing(Cert). 

certPolicyIvRequiresOrgGivenOrSurname(Cert) :- 
  \+givenNameMissing(Cert). 

certPolicyIvRequiresOrgGivenOrSurname(Cert) :- 
  \+surnameMissing(Cert).

certPolicyIvRequireslocalityName(Cert) :- 
  \+localityNameMissing(Cert).

certPolicyIvRequiresStateOrProvinceName(Cert) :- 
  \+stateOrProvinceNameMissing(Cert).

% Seems off but taken from zlint github
certPolicyIvRequiresLocalityOrProvinceName(Cert) :- 
  \+localityNameMissing(Cert).

certPolicyIvRequiresLocalityOrProvinceName(Cert) :- 
  \+stateOrProvinceNameMissing(Cert).

certPolicyIvRequiresCountry(Cert) :- 
  \+caCountryNameMissing(Cert). 

% If certificate asserts policy identifier 
% 2.23.140.1.2.2 then it MUST include
% organizationName, localityName,
% stateOrProvinceName, and countryName

certPolicyOvApplies(Cert) :- 
  certs:certificatePolicies(Cert, "2.23.140.1.2.2").

certPolicyRequiresOrg(Cert) :- 
  \+organizationNameMissing(Cert). 

certPolicyOvRequires(Cert) :- 
  \+organizationNameMissing(Cert), 
  \+localityNameMissing(Cert), 
  \+stateOrProvinceNameMissing(Cert), 
  \+caCountryNameMissing(Cert).

% Postal Code must not appear if 
% organizationName, givenName, or 
% surname fields are absent 

postalCodeProhibtedApplies(Cert) :- 
  organizationNameMissing(Cert).

postalCodeProhibtedApplies(Cert) :- 
  givenNameMissing(Cert).

postalCodeProhibtedApplies(Cert) :- 
  surnameMissing(Cert).

postalCodeProhibted(Cert) :- 
  postalCodeMissing(Cert).

% CAs must not issue certificates 
% longer than 39 months under 
% any circumstances 

maxLifetime(102560094).

validTimeTooLong(Cert) :- 
  maxLifetime(MaxDuration),
  certs:notBefore(Cert, NotBeforeTime),
  certs:notAfter(Cert, NotAfterTime),
  subtract(Duration, NotAfterTime, NotBeforeTime),
  geq(Duration, MaxDuration).

validTimeNotTooLong(Cert) :- 
  \+validTimeTooLong(Cert).

% SAN must appear 
extSanMissing(Cert) :- 
  certs:san(Cert, "").

extSanMissing(Cert) :- 
  certs:sanExt(Cert, false).

extSanNotMissing(Cert) :- 
  \+extSanMissing(Cert).

% The following lints relate to 
% verifying the RSA if used
rsaApplies(Cert) :- 
  certs:keyAlgorithm(Cert, "1.2.840.113549.1.1.1").

% RSA: Public Exponent must be odd
rsaPublicExponentOdd(Cert) :- 
  certs:rsaExponent(Cert, Exp), 
  modulus(1, Exp, 2).

rsaPublicExponentNotTooSmall(Cert) :- 
  certs:rsaExponent(Cert, Exp),
  geq(Exp, 3).

rsaPublicExponentInRange(Cert) :- 
  certs:rsaExponent(Cert, Exp),
  geq(Exp, 65537). 

rsaPublicExponentInRange(Cert) :- 
  certs:rsaExponent(Cert, Exp),
  \+geq(Exp, 115792089237316195423570985008687907853269984665640564039457584007913129639938). 

rsaModOdd(Cert) :- 
  certs:rsaModulus(Cert, Mod), 
  modulus(1, Mod, 2).

rsaModFactorsSmallerThan752(Cert) :- 
  certs:rsaModulus(Cert, Modulus),
  prime_num(Mod),
  modulus(0, Modulus, Mod).

rsaModNoFactorsSmallerThan752(Cert) :- 
  \+rsaModFactorsSmallerThan752(Cert).

rsaModMoreThan2048Bits(Cert) :- 
  certs:rsaModLength(Cert, Length), 
  geq(Length, 2048).



% Root CA Certificate: Bit positions for
% keyCertSign and cRLSign must be set


% CAs MUST NOT issue any new Subscriber 
% certificates or Subordinate CA certificates 
% using SHA-1 after 1 January 2016
subCertOrSubCaNotUsingSha1(Cert) :- 
  \+certs:keyAlgorithm(Cert, "1.2.840.113549.1.1.5"),
  \+certs:keyAlgorithm(Cert, "1.3.14.3.2.27"), 
  \+certs:keyAlgorithm(Cert, "1.2.840.10045.4.1").

% The following are lints for the dnsName 
% under subject alternative name 
dnsNameApplies(Cert) :- 
  \+caCommonNameMissing(Cert), 
  notEmptyNamesExist(Cert), 
  \+commonNameIsIPv4(Cert).

% Characters in labels of DNSNames MUST be alphanumeric, - , _ or *
dnsNameHasBadChar(Cert) :- 
  certs:commonName(Cert, DNSName),
  string_concat(_, Y, DNSName),
  string_concat(A, _, Y),
  string_length(A, 1),
  \+acceptable(A).

dnsNameHasBadChar(Cert) :- 
  certs:san(Cert, DNSName),
  string_concat(_, Y, DNSName),
  string_concat(A, _, Y),
  string_length(A, 1),
  \+acceptable(A).

dnsNameAllCharsAcceptable(Cert) :- 
  \+dnsNameHasBadChar(Cert).

% Wildcards in the left label of DNSName should only be *
dnsNameLeftLabelWildcardIncorrect(Cert) :- 
  certs:commonName(Cert, DNSName), 
  split_string(DNSName, ".", "", [Left | _]), 
  substring("*", Left),
  \+Left = "*". 

dnsNameLeftLabelWildcardIncorrect(Cert) :- 
  certs:san(Cert, DNSName), 
  split_string(DNSName, ".", "", [Left | _]), 
  substring("*", Left),
  \+Left = "*". 

dnsNameLeftLabelWildcardCorrect(Cert) :- 
  \+dnsNameLeftLabelWildcardIncorrect(Cert).

% DNSName labels MUST be less than or equal to 63 characters
dnsNameTooLong(Cert) :- 
  certs:commonName(Cert, Label), 
  string_length(Label, Length), 
  geq(Length, 64).

dnsNameTooLong(Cert) :- 
  certs:san(Cert, Label), 
  string_length(Label, Length), 
  geq(Length, 64).

dnsNameNotTooLong(Cert) :- 
  \+dnsNameTooLong(Cert).

% DNSNames should not have an empty label.
dnsNameIsEmptyLabel(Cert) :- 
  certs:commonName(Cert, ""). 

dnsNameIsEmptyLabel(Cert) :- 
  certs:san(Cert, ""). 

dnsNameIsNotEmptyLabel(Cert) :- 
  \+dnsNameIsEmptyLabel(Cert).

% DNSNames should not contain a bare IANA suffix.
dnsNameContainsBareIANASuffix(Cert) :- 
  certs:commonName(Cert, Label), 
  tld(Label).

dnsNameContainsBareIANASuffix(Cert) :- 
  certs:san(Cert, Label), 
  tld(Label).

dnsNameDoesNotContainBareIANASuffix(Cert) :- 
  \+dnsNameContainsBareIANASuffix(Cert).

% DNSName should not have a hyphen beginning or ending the SLD
dnsNameHyphenInSLD(Cert) :- 
  certs:commonName(Cert, DNSName),
  secondLevelDomain(DNSName, SLD), 
  s_startswith(SLD, "-").

dnsNameHyphenInSLD(Cert) :- 
  certs:san(Cert, DNSName),
  secondLevelDomain(DNSName, SLD), 
  s_startswith(SLD, "-").

dnsNameHyphenInSLD(Cert) :- 
  certs:commonName(Cert, DNSName),
  secondLevelDomain(DNSName, SLD), 
  s_endswith(SLD, "-").

dnsNameHyphenInSLD(Cert) :- 
  certs:san(Cert, DNSName),
  secondLevelDomain(DNSName, SLD), 
  s_endswith(SLD, "-").

dnsNameNoHyphenInSLD(Cert) :- 
  \+dnsNameHyphenInSLD(Cert).

% DNSName MUST NOT contain underscore characters
dnsNameUnderscoreInSLD(Cert) :- 
  certs:commonName(Cert, DNSName),
  secondLevelDomain(DNSName, SLD), 
  substring("_", SLD).

dnsNameUnderscoreInSLD(Cert) :- 
  certs:san(Cert, DNSName),
  secondLevelDomain(DNSName, SLD), 
  substring("_", SLD).

dnsNameNoUnderscoreInSLD(Cert) :- 
  \+dnsNameHyphenInSLD(Cert).

% DNSNames must have a valid TLD
dnsNameRightLabelNotValidTLD(Cert) :- 
  certs:commonName(Cert, DNSName), 
  topLevelDomain(DNSName, TLD), 
  \+tld(TLD).

dnsNameRightLabelNotValidTLD(Cert) :- 
  certs:san(Cert, DNSName), 
  topLevelDomain(DNSName, TLD), 
  \+tld(TLD).

dnsNameRightLabelValidTLD(Cert) :- 
  \+dnsNameRightLabelNotValidTLD(Cert).


dnsNameUnderscoreInTRD(Cert) :- 
  certs:commonName(Cert, DNSName), 
  substring("_", DNSName).

dnsNameUnderscoreInTRD(Cert) :- 
  certs:san(Cert, DNSName), 
  substring("_", DNSName).

dnsNameWildCardOnlyInLeftLabel(Cert) :- 
  certs:commonName(Cert, DNSName), 
  split_string(DNSName, ".", "", [_ | Rest]),
  forall(member(Rest, Word), 
  \+substring("*", Word)).

dnsNameWildCardOnlyInLeftLabel(Cert) :- 
  certs:san(Cert, DNSName), 
  split_string(DNSName, ".", "", [_ | Rest]),
  forall(member(Rest, Word), 
  \+substring("*", Word)).

% Basic Constraints checks
% CA bit set
isCa(Cert) :-
  certs:basicConstraintsExt(Cert, true),
  certs:isCA(Cert, true).

isNotCa(Cert) :- 
  \+isCa(Cert).

% All of the helper methods will be posted below 
organizationNameMissing(Cert) :- 
  certs:organizationName(Cert, "").

givenNameMissing(Cert) :- 
  certs:givenName(Cert, "").

surnameMissing(Cert) :- 
  certs:surname(Cert, "").

stateOrProvinceNameMissing(Cert) :- 
  certs:stateOrProvinceName(Cert, ""). 

localityNameMissing(Cert) :- 
  certs:localityName(Cert, "").

postalCodeMissing(Cert) :- 
  certs:postalCode(Cert, "").

equal(X, Y):-
    X == Y.

larger(X, Y):-
    X > Y.

geq(X, Y):-
    X >= Y.

add(X, Y, Z):-
    X is Y + Z.

subtract(X, Y, Z):-
    X is Y - Z.

modulus(X, Y, Z) :- 
  X is Y mod Z.

s_endswith(String, Suffix):-
    string_concat(_, Suffix, String).

s_startswith(String, Prefix):-
    string_concat(Prefix, _, String).
  
substring(X,S) :-
   sub_string(S, _Before, _Length, _After, X).

% The follow are helper functions for DNSName rules

isIPv4(Addr):-
    split_string(Addr, ".", "", Bytes), length(Bytes, 4),
    forall(member(B, Bytes), (
        number_string(NB, B), 
        NB < 256,
        number_string(NB, SNB), B = SNB /* to avoid leading zeroes */
    )).

commonNameIsIPv4(Cert) :- 
  certs:commonName(Cert, CommonName), 
  isIPv4(CommonName). 

notEmptyNamesExist(Cert) :- 
  \+certs:commonName(Cert, "").

notEmptyNamesExist(Cert) :- 
  \+certs:san(Cert, "").

secondToLast([SLD,_], SLD). 
secondToLast([_|Rest], SLD) :- secondToLast(Rest, SLD).
secondLevelDomain(DNSName, SLD) :- 
  split_string(DNSName, ".", "", Sep),
  secondToLast(Sep, SLD).

%last_element([TLD],TLD).
%last_element([_|List], TLD) :- last_element(List, TLD).
topLevelDomain(DNSName, TLD) :- 
  split_string(DNSName, ".", "", Sep), 
  last(Sep, TLD).


% Start of zlintV2
% check if Cert is a trusted root
isRoot(Cert):-
    certs:fingerprint(Cert, Fingerprint),
    trusted_roots(Fingerprint).

% Helper methods up here
% checks if cert is a root certificate
rootApplies(Cert) :-
	%certs:isCA(Cert, true),
	std:isRoot(Cert).
	%certs:fingerprint(Cert, Fingerprint),
    %trusted_roots(Fingerprint).

isSubCA(Cert) :-
	certs:isCA(Cert, true),
	\+isRoot(Cert).

% check for if it is a subscriber certificate
isSubCert(Cert) :-
	certs:isCA(Cert, false).

 
%  Root CA and Subordinate CA Certificate: 
%  keyUsage extension MUST be present and MUST be marked critical.
caKeyUsagePresentAndCriticalApplies(Cert) :-
	certs:isCA(Cert, true).

caKeyUsagePresent(Cert) :-
	certs:keyUsageExt(Cert, true).

%caKeyUsageCritical(Cert) :-
%	\+caKeyUsagePresentAndCriticalApplies(Cert).

caKeyUsageCritical(Cert) :-
	certs:keyUsageExt(Cert, true),
	certs:keyUsageCritical(Cert, true).


%  Subordinate CA Certificate: certificatePolicies 
%  MUST be present and SHOULD NOT be marked critical.
subCaCertPoliciesExtPresent(Cert) :-
	isSubCA(Cert),
	certs:certificatePoliciesExt(Cert, true).

%subCaCertPoliciesExtPresent(Cert) :-
%	\+isSubCA(Cert).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	subCaCertPoliciesExtPresent(Cert),
	certs:certificatePoliciesCritical(Cert, false).	

subCaCertPoliciesNotMarkedCritical(Cert) :-
	\+isSubCA(Cert).


%  Root CA Certificate: basicConstraints MUST appear as a critical extension
rootBasicConstraintsCritical(Cert) :-
	certs:basicConstraintsExt(Cert, true),
	certs:basicConstraintsCritical(Cert, true).

rootBasicConstraintsCritical(Cert) :-
	\+isRoot(Cert).


%  Root CA Certificate: The pathLenConstraintField SHOULD NOT be present.
% Checks root CA for no length constraint
rootPathLenNotPresent(Cert) :-
	certs:pathLimit(Cert, none).

rootPathLenNotPresent(Cert) :-
	\+isRoot(Cert).


%  Root CA Certificate: extendedKeyUsage MUST NOT be present.
rootExtKeyUseNotPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, false).

rootExtKeyUseNotPresent(Cert) :-
	\+isRoot(Cert).


%  Root CA Certificate: certificatePolicies SHOULD NOT be present.
rootCertPoliciesNotPresent(Cert) :-
	certs:certificatePoliciesExt(Cert, false).

rootCertPoliciesNotPresent(Cert) :-
	\+isRoot(Cert).


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

%  To be considered Technically Constrained, the
%  Subordinate CA: Must include an EKU extension.
subCaEkuPresent(Cert) :-
	isSubCA(Cert),
	certs:extendedKeyUsageExt(Cert, true).

%subCaEkuPresent(Cert) :-
%	\+isSubCA(Cert).


%  Subordinate CA Certificate: extkeyUsage, either id-kp-serverAuth
%  or id-kp-clientAuth or both values MUST be present.
subCaEkuValidFields(Cert) :-
	subCaEkuPresent(Cert),
	certs:extendedKeyUsage(Cert, serverAuth).

subCaEkuValidFields(Cert) :-
	subCaEkuPresent(Cert),
	certs:extendedKeyUsage(Cert, clientAuth).

%subCaEkuValidFields(Cert) :-
%	\+isSubCA(Cert).


%  Subscriber Certificate: certificatePolicies MUST be present
%  and SHOULD NOT be marked critical.
subCertCertPoliciesExtPresent(Cert) :-
	isSubCert(Cert),
	certs:certificatePoliciesExt(Cert, true).

%subCertCertPoliciesExtPresent(Cert) :-
%	\+isSubCert(Cert).

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
	\+isRoot(Cert).


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
	certs:sanExt(Cert, true),
	certs:commonName(Cert, CN),
	certs:san(Cert, SN),
	string_lower(CN, CNL),
	string_lower(SN, SNL),
	equal(CNL, SNL).

%subCertCommonNameFromSan(Cert) :-
%	\+subCertCommonNameFromSanApplies(Cert).


%  Subordinate CA Certificate: cRLDistributionPoints MUST be present 
%  and MUST NOT be marked critical.
% NEED TO CHANGE crlDistributionPoints to crlDistributionPointsExt LATER WHEN CARGO BUILD WORKS
subCaCrlDistributionPointsPresent(Cert) :-
	isSubCA(Cert),
	certs:crlDistributionPointsExt(Cert, true),
	\+certs:crlDistributionPoint(Cert, false).

%subCaCrlDistributionPointsPresent(Cert) :-
%	\+isSubCA(Cert).

subCaCrlDistPointsNotMarkedCritical(Cert) :-
	subCaCrlDistributionPointsPresent(Cert),
	certs:crlDistributionPointsCritical(Cert, false).

subCaCrlDistPointsNotMarkedCritical(Cert) :-
	\+isSubCA(Cert).


%  Subordinate CA Certificate: cRLDistributionPoints MUST contain
%  the HTTP URL of the CAs CRL service.
subCaCrlDistPointContainsHttpUrl(Cert) :-
	subCaCrlDistributionPointsPresent(Cert),
	certs:crlDistributionPoint(Cert, Url),
	s_startswith(Url, "http://").

% another scenario for if there are ldap points before the http
subCaCrlDistPointContainsHttpUrl(Cert) :-
	subCaCrlDistributionPointsPresent(Cert),
	certs:crlDistributionPoint(Cert, Url),
	substring("http://", Url).

subCaCrlDistPointContainsHttpUrl(Cert) :-
	\+isSubCA(Cert).

%  Subscriber Certifcate: cRLDistributionPoints MAY be present.
%  not considered in valid scope
% NEED TO CHANGE crlDistributionPoints to crlDistributionPointsExt LATER WHEN CARGO BUILD WORKS
subCertCrlDistributionPointsPresent(Cert) :-
	isSubCert(Cert),
	certs:crlDistributionPointsExt(Cert, true),
	\+certs:crlDistributionPoint(Cert, false).

%subCertCrlDistributionPointsPresent(Cert) :-
%	\+isSubCert(Cert).

%  Subscriber Certifcate: cRLDistributionPoints MUST NOT be marked critical,
%  and MUST contain the HTTP URL of the CAs CRL service.
subCertCrlDistPointsNotMarkedCritical(Cert) :-
	certs:crlDistributionPointsCritical(Cert, false).

subCertCrlDistPointsNotMarkedCritical(Cert) :-
	certs:crlDistributionPoint(Cert, false).

subCertCrlDistPointsNotMarkedCritical(Cert) :-
	\+isSubCert(Cert).

% sub cert: cRLDistributionPoints MUST contain the HTTP URL of the CAs CRL service
subCertCrlDistPointContainsHttpUrl(Cert) :-
	certs:crlDistributionPoint(Cert, Url),
	s_startswith(Url, "http://").

subCertCrlDistPointContainsHttpUrl(Cert) :-
	certs:crlDistributionPoint(Cert, Url),
	s_occurrences(Url, "http://", N),
	equal(N, 1).

subCertCrlDistPointContainsHttpUrl(Cert) :-
	certs:crlDistributionPoint(Cert, false).

subCertCrlDistPointContainsHttpUrl(Cert) :-
	\+isSubCert(Cert).

%  Subscriber Certificate: authorityInformationAccess MUST NOT be marked critical
% helper function
subCertAIAPresent(Cert) :-
	isSubCert(Cert),
	certs:authorityInfoAccessExt(Cert, true).

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
subCAAIAPresent(Cert) :-
	isSubCA(Cert),
	certs:authorityInfoAccessExt(Cert, true).

subCAAIAContainsOCSPUrl(Cert) :-
	certs:authorityInfoAccessExt(Cert, true),
	certs:authorityInfoAccessLocation(Cert, "OCSP", Url),
	s_startswith(Url, "http://").

subCAAIAContainsOCSPUrl(Cert) :-
	\+isSubCA(Cert).


%  Subordinate CA Certificate: authorityInformationAccess SHOULD
%  also contain the HTTP URL of the Issuing CAs certificate.
subCAAIAContainsIssuingCAUrl(Cert) :-
	certs:authorityInfoAccessExt(Cert, true),
	certs:authorityInfoAccessLocation(Cert, "CA Issuers", Url),
	s_startswith(Url, "http://").

subCAAIAContainsIssuingCAUrl(Cert) :-
	\+isSubCA(Cert).


%  the CA MUST establish and follow a documented procedure[^pubsuffix] that
%  determines if the wildcard character occurs in the first label position to
%  the left of a “registry‐controlled” label or “public suffix”
dnsWildcardNotLeftOfPublicSuffixApplies(Cert) :-
	isSubCert(Cert),
	certs:sanExt(Cert, true).

dnsWildcardNotLeftOfPublicSuffixApplies(Cert) :-
	isSubCert(Cert),
	\+certs:commonName(Cert, "").

dnsWildcardLeftOfPublicSuffix(San) :-
	string_concat("*.", X, San),
	public_suffix(X).

dnsWildcardLeftOfPublicSuffix(San) :-
	public_suffix(Pubsuff),
	string_concat("*.", Pubsuff, NotAllowed),
	s_endswith(San, NotAllowed).

dnsWildcardNotLeftOfPublicSuffix(Cert) :-
	certs:sanExt(Cert, true),
	certs:san(Cert, San),
	\+dnsWildcardLeftOfPublicSuffix(San).

dnsWildcardNotLeftOfPublicSuffix(Cert) :-
	certs:commonName(Cert, CommonName),
	\+dnsWildcardLeftOfPublicSuffix(CommonName).

dnsWildcardNotLeftOfPublicSuffix(Cert) :-
 	\+isSubCert(Cert).


% Start of zlintV3
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
  certs:spkiDSAParameters(Cert, _, _, _).
  
dsaProperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, _),
  equal(L, 2048),
  equal(N, 224).

dsaProperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, _),
  equal(L, 2048),
  equal(N, 256).

dsaProperModulusOrDivisorSize(Cert) :-
  certs:spkiDSAParameters(Cert, L, N, _),
  equal(L, 3072),
  equal(N, 256).

dsaProperModulusOrDivisorSize(Cert) :-
  \+certs:spkiDSAParameters(Cert, _, _, _).
  

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