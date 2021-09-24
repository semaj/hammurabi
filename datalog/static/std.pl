:- module(std, [
    nameMatches/1,
    nameMatchesCN/1,
    nameMatchesSAN/1,
    isTimeValid/1,
    usageAllowed/2,
    isCA/1,
    isRoot/1,
    pathLengthOkay/3,
    maxIntermediatesOkay/1,
    descendant/2
]).

:-style_check(-singleton).
:- use_module(env).
:- use_module(certs).
:- use_module(ext).
:- use_module(checks).


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
    ext:equal(Pattern, CommonName).


% domain name matches one of the names in SAN
nameMatchesSAN(Cert) :-
    env:domain(D),
    certs:san(Cert, Name),
    \+ext:s_containstldwildcard(Name),
    stringMatch(Name, D).

% domain name matches common name
nameMatchesCN(Cert):-
    env:domain(D),
    certs:commonName(Cert, Subject),
    \+ext:s_containstldwildcard(Subject),
    stringMatch(Subject, D).

% domain name matches any
nameMatches(Cert):-
  nameMatchesSAN(Cert).

nameMatches(Cert):-
  nameMatchesCN(Cert).

% Error reporting clause
isTimeValid(Cert):-
    checks:timeValidCheckEnabled(false).

% time validity check. between Lower and Upper
isTimeValid(Cert):-
  % ext:equal(T, 1618246820),
    ext:now(T),
    certs:notBefore(Cert, Lower),
    certs:notAfter(Cert, Upper),
    ext:larger(T, Lower),
    ext:larger(Upper, T).

% check if key usage allowed
% keyUsage extension exists clause
usageAllowed(Cert, Usage):-
    certs:keyUsageExt(Cert, true),
    certs:keyUsage(Cert, Usage).

% check if Cert is a trusted root
isRoot(Cert):-
    certs:fingerprint(Cert, Fingerprint),
    env:trusted_roots(Fingerprint).

% Error reporting clause
isCA(Cert):-
    checks:parentNotCACheckEnabled(false).

% Basic Constraints checks
% CA bit set
isCA(Cert):-
    certs:basicConstraintsExt(Cert, true),
    certs:isCA(Cert, true).

% Error reporting clause
pathLengthOkay(Cert, ChainLen, SelfCount):-
    checks:chainLengthCheckEnabled(false),
    ext:geq(ChainLen, ChainLen),
    ext:geq(SelfCount, SelfCount).

% Path length is okay if the extension doesn't exist
pathLengthOkay(Cert, ChainLen, SelfCount) :-
  certs:basicConstraintsExt(Cert, false),
  ext:geq(ChainLen, ChainLen),
  ext:geq(SelfCount, Selfcount).

% Basic Constraints checks
% Path length constraint
pathLengthOkay(Cert, ChainLen, SelfCount):-
    certs:basicConstraintsExt(Cert, true),
    certs:pathLimit(Cert, Limit),
    ext:add(ChainLen, Effective, SelfCount),
    ext:larger(Limit, Effective).

pathLengthOkay(Cert, ChainLen, SelfCount):-
    certs:basicConstraintsExt(Cert, true),
    certs:pathLimit(Cert, none),
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
descendant(Cert, Y):-
    certs:issuer(Cert, Y),
    ext:unequal(Cert, Y).

% descendant. also works for ancestor
% chain clause
descendant(Cert, Y):-
    certs:issuer(Cert, Y),
    ext:unequal(Cert, Z),
    descendant(Z, Y).

