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
