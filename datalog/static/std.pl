:- module(std, [
    nameMatches/1,
    nameMatchesCN/1,
    nameMatchesSAN/1,
    isTimeValid/1,
    extendedKeyUsageExpected/3,
    usageAllowed/2,
    isCA/1,
    isNotCA/1,
    isRoot/1,
    pathLengthOkay/3,
    maxIntermediatesOkay/1,
    descendant/2,
    ipToNumber/6,
    hostInNetwork/2,
    basicsWork/1,
    isCert/1
]).

:- use_module(env).
:- use_module(certs).
:- use_module(cert_0).
:- use_module(cert_1).
:- use_module(ext).
:- use_module(browser).
:- use_module(checks).


% Sugar
% is a Cert if it has serial number
isCert(Cert):-
    certs:serialNumber(Cert, Serial).

% dotted quad to decimal util function
% IPv4 only
ipToNumber(Byte1, Byte2, Byte3, Byte4, Mask, N):-
    % create mask. Shift 255.255.255.255 by Mask
    ext:b_lshift(M, 4294967295, Mask),
    % make decimal from dotted quad and apply mask
    ext:b_lshift(SB1, Byte1, 24),
    ext:b_lshift(SB2, Byte2, 16),
    ext:b_lshift(SB3, Byte3, 8),
    ext:add(R1, SB1, SB2),
    ext:add(R2, SB3, Byte4),
    ext:add(R3, R1, R2),
    ext:b_and(N, R3, M).

% check if host is in network
hostInNetwork(HostIP, Network):-
    b_and(N, HostIP, Network),
    Network = N.

% common name match function
% wildcard clause
stringMatch(Pattern, CommonName):-
    ext:s_startswith(Pattern, "*."),
    ext:s_substring(Pattern, 1, 0, P),
    ext:s_endswith(CommonName, P),
    ext:s_occurrences(Pattern, ".", N),
    ext:s_occurrences(CommonName, ".", N).

% common name match function
% exact clause
stringMatch(Pattern, CommonName):-
    Pattern = CommonName.


% domain name matches one of the names in SAN
nameMatchesSAN(Cert) :-
    env:domain(D),
    certs:extensionValues(Cert, "SubjectAlternativeNames", Name),
    \+ext:s_containstldwildcard(Name),
    stringMatch(Name, D).

% domain name matches common name
nameMatchesCN(Cert):-
    env:domain(D),
    certs:subject(Cert, Subject, S2, S3, S4, S5),
    \+ext:s_containstldwildcard(Subject),
    stringMatch(Subject, D).

% domain name matches any
nameMatches(Cert):-
  nameMatchesSAN(Cert).

nameMatches(Cert):-
  nameMatchesCN(Cert).

% Error reporting clause
isTimeValid(Cert):-
    checks:timeValidCheckEnabled(false),
    std:isCert(Cert).

% time validity check. between Lower and Upper
isTimeValid(Cert):-
    ext:now(T),
    certs:validity(Cert, Lower, Upper),
    ext:larger(T, Lower),
    ext:larger(Upper, T).

extendedKeyUsageExpected(Cert, Usage, Expected):-
    certs:extensionValues(Cert, "ExtendedKeyUsage", Usage, Expected).

% check if extension does not exist
extensionAbsent(Cert, Extension):-
    certs:extensionExists(Cert, Extension, false).

% check if key usage allowed
% keyUsage extension exists clause
usageAllowed(Cert, Usage):-
    certs:extensionExists(Cert, "KeyUsage", true),
    certs:extensionValues(Cert, "KeyUsage", Usage, true).

% check if Cert is a trusted root
isRoot(Cert):-
    certs:fingerprint(Cert, Fingerprint),
    env:trusted_roots(Fingerprint).

% Error reporting clause
isCA(Cert):-
    checks:parentNotCACheckEnabled(false),
    std:isCert(Cert).

% Basic Constraints checks
% CA bit set
isCA(Cert):-
    certs:extensionExists(Cert, "BasicConstraints", true),
    certs:extensionValues(Cert, "BasicConstraints", true, Limit).

isNotCA(Cert):-
    certs:extensionExists(Cert, "BasicConstraints", false).

isNotCA(Cert):-
    certs:extensionExists(Cert, "BasicConstraints", true),
    certs:extensionValues(Cert, "BasicConstraints", false, Limit).

% Error reporting clause
pathLengthOkay(Cert, ChainLen, SelfCount):-
    checks:chainLengthCheckEnabled(false),
    std:isCert(Cert),
    ext:geq(ChainLen, ChainLen),
    ext:geq(SelfCount, SelfCount).

% Path length is okay if the extension doesn't exist
pathLengthOkay(Cert, ChainLen, SelfCount) :-
  certs:extensionExists(Cert, "BasicConstraints", false),
  ext:geq(ChainLen, ChainLen),
  ext:geq(SelfCount, Selfcount).

% Basic Constraints checks
% Path length constraint
pathLengthOkay(Cert, ChainLen, SelfCount):-
    certs:extensionExists(Cert, "BasicConstraints", true),
    certs:extensionValues(Cert, "BasicConstraints", Ca, Limit),
    ext:add(ChainLen, Effective, SelfCount),
    ext:larger(Limit, Effective).

pathLengthOkay(Cert, ChainLen, SelfCount):-
    certs:extensionExists(Cert, "BasicConstraints", true),
    certs:extensionValues(Cert, "BasicConstraints", Ca, none),
    ext:geq(ChainLen, ChainLen),
    ext:geq(SelfCount, SelfCount).

maxIntermediatesOkay(ChainLen):-
    checks:chainLengthCheckEnabled(false),
    ext:larger(ChainLen, -1),
    ext:larger(1000, ChainLen).

% Custom limit on intermediate certs check
% exempts trusted certs from limit
maxIntermediatesOkay(ChainLen):-
    env:max_intermediates(M),
    ext:larger(M, ChainLen).

% descendant. also works for ancestor
% direct parent clause
descendant(X, Y):-
    certs:issuer(X, Psub, S2, S3, S4, S5),
    certs:subject(Y, Psub, S2, S3, S4, S5),
    ext:unequal(X, Y).

% descendant. also works for ancestor
% chain clause
descendant(X, Y):-
    certs:issuer(X, Psub, S2, S3, S4, S5),
    certs:subject(Z, Psub, S2, S3, S4, S5),
    ext:unequal(X, Z),
    descendant(Z, Y).


% Error reporting clause
internalCheck(Cert):-
    checks:aCCCheckEnabled(false),
    std:isCert(Cert).

% run internal checks of cert
% hard-coded. need to find better solution
internalCheck(Cert):-
   Cert = cert_0,
   cert_0:cert_0(Cert).

internalCheck(Cert):-
   Cert = cert_1,
   cert_1:cert_1(Cert).

% check basics like time validity
% and self-verification
basicsWork(Cert):-
    isTimeValid(Cert),
    internalCheck(Cert).


