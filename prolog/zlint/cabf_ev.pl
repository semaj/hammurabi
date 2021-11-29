:- use_module("../static/ev").

% EV certificates must include serialNumber in subject
evSerialNumberPresent(SerialNumber) :-
    SerialNumber \= "".


maxLifetimeEv(71003142).
% EV certificates must be 27 months in validity or less
evValidTimeNotTooLong(NotBefore, NotAfter) :-
    maxLifetimeEv(MaxDuration),
    ext:subtract(Duration, NotBefore, NotAfter),
    ext:geq(MaxDuration, Duration).

% Check that a certificate is a subscriber cert and 
% has a subject name ending in ".onion"
isOnion(Cert, San) :-
    certs:isCA(Cert, false),
    s_endswith(San, ".onion").

maxLifetimeOnion(39446190).
% certificates with .onion names can not be valid for 
% more than 15 months, maxOnionValidityMonths
onionValidTimeNotTooLong(NotBefore, NotAfter) :-
    maxLifetimeOnion(MaxDuration),
    ext:subtract(Duration, NotBefore, NotAfter),
    ext:geq(MaxDuration, Duration).

% EV certificates must include businessCategory in subject
evBusinessCategoryPresent(BusinessCategory) :-
    BusinessCategory \= "".

% EV certificates must include countryName in subject
evCountryNamePresent(CountryName) :-
    CountryName \= "".
    
% check a subscriber certificate
isSubCert(Cert) :-
	certs:isCA(Cert, false).

evOrganizationIdPresent(Cert) :-
   % check applies
   certs:certificatePoliciesExt(Cert, true),
   certs:certificatePolicies(Cert, Oid), 
   ev:evPolicyOid(Oid, _, _, _, _, _),
   certs:organizationalIdentifier(Cert, Orgid), 
   certs:notBefore(Cert, Lower),
   Jan312020 = 1580446800,
   Lower >= Jan312020,
   % body
   \+certs:cabfOrganizationIdentifierExt({}, false).
   
evOrganizationNamePresent(Cert) :-   
   % check applies
   certs:certificatePoliciesExt(Cert, true),
   certs:certificatePolicies(Cert, Oid), 
   ev:evPolicyOid(Oid, _, _, _, _, _),
   isSubCert(Cert),
   % body
   certs:organizationName(Cert, OrgName),
   OrgName \= "".
