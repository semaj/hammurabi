:- module(chrome, [
    verified/1
]).

:- style_check(-singleton).
:- use_module(certs).
:- use_module(std).
:- use_module(chrome_env).

checkKeyUsage(Cert) :-
  certs:extensionExists(Cert, "KeyUsage", false).

checkKeyUsage(Cert) :-
  std:isCA(Cert),
  std:usageAllowed(Cert, "keyCertSign").

checkKeyUsage(Cert) :-
  std:isNotCA(Cert),
  std:usageAllowed(Cert, "digitalSignature").

checkKeyUsage(Cert) :-
  std:isNotCA(Cert),
  std:usageAllowed(Cert, "keyEncipherment").

checkKeyUsage(Cert) :-
  std:isNotCA(Cert),
  std:usageAllowed(Cert, "keyAgreement").


time_2016_06_01(1464739200). % 01 Jun 2016
time_2017_12_01(1512086400). % 01 Dec 2017

symantec_untrusted(Cert):-
  certs:validity(Cert, Start, End),
  time_2016_06_01(June2016),
  ext:larger(Jun2016, Start).

symantec_untrusted(Cert):-
  certs:validity(Cert, Start, End),
  time_2017_12_01(Dec2017),
  ext:larger(Start, Dec2017).

% if legacy symantec and
% symantec enforcement on OR untrusted symantec
% legacy: if it's a symantec root and not an exception/managed
% untrusted: issued after 01 dec 2017 or before 01 jun 2016
bad_symantec(Cert):-
  certs:fingerprint(Cert, Fingerprint),
  chrome_env:symantec_root(Fingerprint),
  \+chrome_env:symantec_exception(Fingerprint),
  \+chrome_env:symantec_managed_ca(Fingerprint),
  symantec_untrusted(Cert).

% Error reporting clause
inCRLSets(Cert):-
  checks:revokedCheckEnabled(true),
  certs:fingerprint(Cert, Fingerprint),
  crl_set(Fingerprint).

% XXX reorganize/rename
isRoot(Cert):-
  certs:fingerprint(Cert, Fingerprint),
  chrome_env:trusted(Fingerprint),
  env:domain(Domain),
  chrome_env:no_name_constraint_violation(Cert, Domain).


parent(C, P, ChainLen):-
    certs:issuer(C, Sub1, Sub2, Sub3, Sub4, Sub5),
    certs:subject(P, Sub1, Sub2, Sub3, Sub4, Sub5),
    isRoot(P),
    std:pathLengthOkay(P, ChainLen, 0).

checkKeyCertSign(Cert) :-
  std:usageAllowed(Cert, "keyCertSign").

checkKeyCertSign(Cert) :-
  certs:extensionExists(Cert, "KeyUsage", false).

parent(C, P, ChainLen):-
    certs:issuer(C, Sub1, Sub2, Sub3, Sub4, Sub5),
    certs:subject(P, Sub1, Sub2, Sub3, Sub4, Sub5),
    std:isCA(P),
    checkKeyCertSign(P),
    std:pathLengthOkay(P, ChainLen, 0).


verified(Cert, ChainLength, Leaf):-
  std:isTimeValid(Cert),
  ext:larger(20, ChainLength), % Artificial max chain length -- XXX
  \+bad_symantec(Cert),
  isRoot(Cert),
  std:isCert(Leaf),
  ext:geq(ChainLength, 0).

verified(Cert, ChainLength, Leaf):-
  chrome_env:strong_signature(Cert),
  std:isTimeValid(Cert),
  checkKeyUsage(Cert),
  checkExtendedKeyUsage(Cert),
  ext:larger(20, ChainLength), % Artificial max chain length -- XXX
  \+bad_symantec(Cert),
  \+inCRLSets(Cert),
  parent(Cert, Parent, ChainLength),
  ext:add(ChainLenNew, ChainLength, 1),
  verified(Parent, ChainLenNew, Leaf).

% Error reporting clause
chromeNameMatches(Cert) :-
  checks:domainMatchCheckEnabled(false),
  std:isCert(Cert).

chromeNameMatches(Cert) :-
  certs:extensionExists(Cert, "SubjectAlternativeNames", true),
  std:nameMatchesSAN(Cert).

% Check CN ONLY if SAN not present
chromeNameMatches(Cert) :-
  certs:extensionExists(Cert, "SubjectAlternativeNames", false),
  std:nameMatchesCN(Cert).

checkExtendedKeyUsage(Cert):-
  std:extendedKeyUsageExpected(Cert, "serverAuth", true).

checkExtendedKeyUsage(Cert) :-
  certs:extensionExists(Cert, "ExtendedKeyUsage", false).

checkExtendedKeyUsage(Cert):-
  std:isNotCA(Cert),
  std:extendedKeyUsageExpected(Cert, "serverAuth", true).

verified(Cert):-
  chromeNameMatches(Cert),
  checkExtendedKeyUsage(Cert),
  chrome_env:leaf_duration_valid(Cert),
  verified(Cert, -1, Cert). % 0 is the chain length, which is the number of CAs allowed
