% The serial number MUST be a positive integer assigned by the CA to each certificate.
serialNumberPositive(SerialNumber) :- 
    SerialNumber > 0. 

% Conforming CAs MUST NOT use serialNumber values longer than 20 octets. 
serialNumberNoLongerThan20Octets(SerialNumber) :- 
    number_string(StrVar, SerialNumber)
    atom_chars(StrVar, ListVar), 
    length(ListVar, LengthVar),
    LengthVar < 20. 

% The issuer field MUST contain a non-empty distinguished name (DN).
issuerFieldNotEmpty(DN) :- 
    DN \= "".

% Unique identifier fields MUST only appear if the version is 2 or 3
certUniqueIndentifierVersion2or3(Version) :- 
    Version == 2.

certUniqueIndentifierVersion2or3(Version) :- 
    Version == 3.

% CAs conforming to this profile MUST NOT generate certificates with unique identifiers.
certContainsUniqueIdentifier(UniqueIdentifer) :- 
    UniqueIdentifer \= "". 

% Whenever such identities (anything in a SAN) are to be bound into a certificate, 
% the subject alternative name (or issuer alternative name) extension MUST be used


getCertFields(Cert):-
  certs:crlDistributionPointsExt(Cert, crlDistPointExt),
  certs:crlDistributionPoint(Cert, crlDistPoint).

% ca basicConstraints MUST appear as a critical extension
caBasicConstraintsCritical(Cert) :-
    certs:basicConstraintsExt(Cert, true),
    certs:basicConstraintsCritical(Cert, true).

% CA Certificates subject field MUST not be empty 
% and MUST have a non-empty distinguished name
caSubjectFieldNotEmpty(Cert) :-
    \+certs:commonName(Cert, "").
    % CommonName \= "".

caSubjectFieldNotEmpty(Cert) :-
    \+certs:localityName(Cert, "").

caSubjectFieldNotEmpty(Cert) :-
    certs:surname(Cert, "").

caSubjectFieldNotEmpty(Cert) :-
    \+certs:organizationName(Cert, "").

caSubjectFieldNotEmpty(Cert) :-
    \+certs:stateOrProvinceName(Cert, ""). 

caSubjectFieldNotEmpty(Cert) :-
    \+certs:postalCode(Cert, "").

% The extensions field MUST only appear in version 3 certificates
% need to find all extensions


% A DistributionPoint from the CRLDistributionPoints extension
% MUST NOT consist of only the reasons field; either distributionPoint
% or CRLIssuer must be present
% check what it looks like when we run the two example certificates test it
crlDistributionPointComplete(Cert) :-
    certs:crlDistributionPointsExt(Cert, true),
	\+certs:crlDistributionPoint(Cert, false).

% The dNSName " " MUST NOT be used
extSanSpaceDNSname(Cert) :-
    \+certs:san(Cert, " ").

% Where it appears, the pathLenConstraint field MUST be 
% greater than or equal to zero
pathLenConstraintZeroOrGreater(Cert) :-
    certs:pathLimit(Cert, PathLimit),
    PathLimit >= 0.


% CAs must include keyIdentifer field of AKI in all non-self-issued certificates
% need to parse for Authority Key Identifier