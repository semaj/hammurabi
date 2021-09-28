:- module(firefox, [
  certVerifiedChain/1,
  verifiedLeaf/11
]).

:- style_check(-singleton).
:- use_module(certs).
:- use_module(env).
:- use_module(std).
:- use_module(ev).
:- use_module(firefox_env).
:- use_module(library(clpfd)).


% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
nameConstraintValid(_, RootFingerprint) :-
  firefox_env:trustedRoots(RootFingerprint),
  \+firefox_env:anssiFingerprint(RootFingerprint),
  \+firefox_env:tubitak1Fingerprint(RootFingerprint).

nameConstraintValid(LeafSANList, RootFingerprint) :-
  firefox_env:tubitak1Fingerprint(RootFingerprint),
  firefox_env:tubitak1Subtree(Tree),
  member(Name, LeafSANList),
  std:stringMatch(Tree, Name).

nameConstraintValid(LeafSANList, RootFingerprint) :-
  firefox_env:anssiFingerprint(RootFingerprint),
  firefox_env:anssiSubtree(Tree),
  member(Name, LeafSANList),
  std:stringMatch(Tree, Name).

notRevoked(Lower, Upper, EVStatus, StapledResponse, OcspResponse) :-
  shortLived(Lower, Upper);
  notOCSPRevoked(EVStatus, StapledResponse, OcspResponse).


notOCSPRevoked(_, _, OcspResponse) :-
  OcspResponse = [].

notOCSPRevoked(_, _, OcspResponse) :-
  OcspResponse = [valid, not_expired, verified, good].

notOCSPRevoked(EVStatus, StapledResponse, OcspResponse) :-
  EVStatus = not_ev,
  StapledResponse = [],
  (
    OcspResponse = [invalid, _, _, _];
    OcspResponse = [_, expired, _, _];
    OcspResponse = [_, _, not_verified, _]
  ).

notOCSPRevoked(EVStatus, StapledResponse, OcspResponse) :-
  EVStatus = not_ev,
  StapledResponse = [verified, not_expired, valid, good],
  (
    OcspResponse = [invalid, _, _, _];
    OcspResponse = [_, expired, _, _];
    OcspResponse = [_, _, not_verified, _]
  ).


tenDaysInSeconds(864001).

shortLived(Lower, Upper) :-
  tenDaysInSeconds(ValidDuration),
  Upper - Lower #< ValidDuration.

keyUsageValid(_, KeyUsage) :-
  KeyUsage = [].

keyUsageValid(BasicConstraints, KeyUsage) :-
  std:isCA(BasicConstraints),
  member(keyCertSign, KeyUsage).

keyUsageValid(BasicConstraints, KeyUsage) :-
  \+std:isCA(BasicConstraints),
  (
    member(digitalSignature, KeyUsage);
    member(keyEncipherment, KeyUsage);
    member(keyAgreement, KeyUsage)
  ).

extKeyUsageValid(BasicConstraints, ExtKeyUsage) :-
  std:isCA(BasicConstraints),
  member(serverAuth, ExtKeyUsage).


extKeyUsageValid(BasicConstraints, ExtKeyUsage) :-
  \+std:isCA(BasicConstraints),
  member(serverAuth, ExtKeyUsage),
  \+member(oCSPSigning, ExtKeyUsage).

extKeyUsageValid(_, ExtKeyUsage) :-
  ExtKeyUsage = [].

checkKeyCertSign(KeyUsage) :-
  KeyUsage = []; member(keyCertSign, KeyUsage).


strongSignature(Algorithm) :-
  % ecdsa with sha1
  Algorithm \== "1.2.840.10045.4.1",
  % rsa signature with sha1
  Algorithm \== "1.3.14.3.2.29",
  % rsa encryption with sha1
  Algorithm \== "1.2.840.113549.1.1.5".


firefoxNameMatches(SANList, _):-
  env:domain(D),
  std:nameMatchesSAN(D, SANList).

% Check CN ONLY if SAN not present
firefoxNameMatches(SANList, Subject) :-
  SANList = [],
  env:domain(D),
  std:nameMatchesCN(D, Subject).

% in seconds
duration27MonthsPlusSlop(71712000).

leafDurationValid(EVStatus, _, _):-
  EVStatus = not_ev.

leafDurationValid(EVStatus, Lower, Upper):-
  EVStatus = ev,
  duration27MonthsPlusSlop(ValidDuration),
  Upper - Lower #< ValidDuration.

notCrl(F):-
    var(F), F = "".

notCrl(F):-
    nonvar(F), \+firefox_env:oneCrl(F).


isEVChain(Cert) :-
  certs:certificatePoliciesExt(Cert, true),
  certs:certificatePolicies(Cert, Oid), 
  evPolicyOid(Oid, _, _, _, _, _),
  certs:issuer(Cert, P),
  isEVIntermediate(P, Oid).

isEVIntermediate(Cert, Oid) :-
  certs:fingerprint(Cert, RootFingerprint),
  firefox_env:trustedRoots(RootFingerprint),
  certs:serialNumber(Cert, Serial),
  ev:evPolicyOid(Oid, Serial).

isEVIntermediate(Cert, Oid) :-
  certs:certificatePoliciesExt(Cert, true),
  (ev:evPolicyOid(Oid, _); ev:anyPolicyOid(Oid)),
  certs:certificatePolicies(Cert, Oid),
  certs:issuer(Cert, P),
  isEVIntermediate(P, Oid).

getEVStatus(Cert, EVStatus):-
  (isEVChain(Cert), EVStatus = ev);
  EVStatus = not_ev.

verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage):-
  firefox_env:trustedRoots(Fingerprint),
  \+firefox_env:symantecFingerprint(Fingerprint),
  std:isTimeValid(Lower, Upper),
  nameConstraintValid(LeafSANList, Fingerprint),
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage).

verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):- 
  notCrl(Fingerprint),
  std:isTimeValid(Lower, Upper),
  strongSignature(Algorithm),
  keyUsageValid(BasicConstraints, KeyUsage),
  extKeyUsageValid(BasicConstraints, ExtKeyUsage),
  notRevoked(Lower, Upper, EVStatus, StapledResponse, OcspResponse).

verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):- 
  \+std:isCA(BasicConstraints),
  env:domain(Subject),
  firefoxNameMatches(SANList, Subject),
  leafDurationValid(EVStatus, Lower, Upper),
  verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse).

certVerifiedNonLeaf(Cert, LeafSANList, EVStatus):-
  certs:fingerprint(Cert, Fingerprint),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  (
    (
      verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse), 
      certs:issuer(Cert, Parent),
      certVerifiedNonLeaf(Parent, LeafSANList, EVStatus)
    );
    verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage)
  ).

certVerifiedLeaf(Cert, EVStatus):-
  certs:fingerprint(Cert, Fingerprint),
  findall(Name, certs:san(Cert, Name), SANList),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  certs:stapledResponse(Cert, StapledResponse),
  certs:ocspResponse(Cert, OcspResponse),
  verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse).

certVerifiedChain(Cert):-
  getEVStatus(Cert, EVStatus),
  certVerifiedLeaf(Cert, EVStatus),
  findall(Name, certs:san(Cert, Name), SANList),
  certs:issuer(Cert, Parent),
  certVerifiedNonLeaf(Parent, SANList, EVStatus).