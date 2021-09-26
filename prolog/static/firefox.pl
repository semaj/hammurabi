:- module(firefox, [
  verified_firefox/18
]).

:- use_module(firefox_env).
:- use_module(env).
:- use_module(std).
:- use_module(library(clpfd)).


% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
nameConstraintValid(_, RootFingerprint) :-
  firefox_env:trusted_roots(RootFingerprint),
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

notRevoked(Lower, Upper, CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  shortLived(Lower, Upper);
  notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse).


notOCSPRevoked(_, _, _, OcspResponse) :-
  OcspResponse = [].

notOCSPRevoked(_, _, _, OcspResponse) :-
  OcspResponse = [verified, not_expired, valid, good].

notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  \+std:isEV(CertPolicies, RootSubject),
  StapledResponse = [],
  (
    OcspResponse = [invalid, _, _, _];
    OcspResponse = [_, expired, _, _];
    OcspResponse = [_, _, not_verified, _]
  ).

notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  \+std:isEV(CertPolicies, RootSubject),
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

leafDurationValid(CertPolicies, _, _, RootSubject):-
  \+std:isEV(CertPolicies, RootSubject).

leafDurationValid(CertPolicies, Lower, Upper, RootSubject):-
  std:isEV(CertPolicies, RootSubject),
  duration27MonthsPlusSlop(ValidDuration),
  Upper - Lower #< ValidDuration.

notCrl(F):-
    var(F), F = "".

notCrl(F):-
    nonvar(F), \+firefox_env:oneCrl(F).

verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage):-
  firefox_env:trusted_roots(Fingerprint),
  \+firefox_env:symantecFingerprint(Fingerprint),
  std:isTimeValid(Lower, Upper),
  nameConstraintValid(LeafSANList, Fingerprint),
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage).

verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse):- 
  notCrl(Fingerprint),
  std:isTimeValid(Lower, Upper),
  strongSignature(Algorithm),
  keyUsageValid(BasicConstraints, KeyUsage),
  extKeyUsageValid(BasicConstraints, ExtKeyUsage),
  notRevoked(Lower, Upper, CertPolicies, RootSubject, StapledResponse, OcspResponse).

verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse):- 
  \+std:isCA(BasicConstraints),
  env:domain(Subject),
  firefoxNameMatches(SANList, Subject),
  leafDurationValid(CertPolicies, Lower, Upper, RootSubject),
  verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse).

certVerifiedNonLeaf(Cert, LeafSANList):-
  certs:fingerprint(Cert, Fingerprint),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  (
    (
      verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse):- 
      certs:issuer(Cert, Parent),
      certVerifiedNonLeaf(Parent)
    );
    verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage)
  ).

certVerifiedLeaf(Cert):-
  certs:fingerprint(Cert, Fingerprint),
  findall(Name, certs:san(Cert, Name), SANList),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  findall(Policy, certs:certificatePolicies(Cert, Policy), CertPolicies),
  findall(Policy, certs:certificatePolicies(Cert, Policy), CertPolicies),

  verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse).

certVerifiedChain(Cert):-
  certVerifiedLeaf(Cert),
  findall(Name, certs:san(Cert, Name), SANList),
  certs:issuer(Cert, Parent),
  certVerifiedNonLeaf(Parent, SANList).