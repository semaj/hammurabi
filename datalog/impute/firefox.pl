:- module(firefox, [
  verified_firefox/18
]).

:- use_module(firefox_env).
:- use_module(std).
:- use_module(library(clpfd)).


% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
nssNameConstraintValid(_, RootFingerprint) :-
  firefox_env:trusted_roots(RootFingerprint),
  \+firefox_env:anssiFingerprint(RootFingerprint),
  \+firefox_env:tubitak1Fingerprint(RootFingerprint).

nssNameConstraintValid(LeafSANList, RootFingerprint) :-
  firefox_env:tubitak1Fingerprint(RootFingerprint),
  firefox_env:tubitak1Subtree(Tree),
  member(Name, LeafSANList),
  std:stringMatch(Tree, Name).

nssNameConstraintValid(LeafSANList, RootFingerprint) :-
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
    OcspResponse = [not_verified, _, _, _];
    OcspResponse = [_, _, invalid, _];
    OcspResponse = [_, expired, _, _]
  ).

notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  \+std:isEV(CertPolicies, RootSubject),
  StapledResponse = [verified, not_expired, valid],
  (
    OcspResponse = [not_verified, _, _, _];
    OcspResponse = [_, expired, _, _];
    OcspResponse = [_, _, invalid, _]
  ).


tenDaysInSeconds(864001).

shortLived(Lower, Upper) :-
  tenDaysInSeconds(ValidDuration),
  Upper - Lower #< ValidDuration.

checkKeyUsage(_, KeyUsage) :-
  KeyUsage = [].

checkKeyUsage(BasicConstraints, KeyUsage) :-
  std:isCA(BasicConstraints),
  member(keyCertSign, KeyUsage).

checkKeyUsage(BasicConstraints, KeyUsage) :-
  \+std:isCA(BasicConstraints),
  (
    member(digitalSignature, KeyUsage);
    member(keyEncipherment, KeyUsage);
    member(keyAgreement, KeyUsage)
  ).

checkExtendedKeyUsage(BasicConstraints, ExtKeyUsage) :-
  member(ExtKeyUsage, serverAuth),
  (
    std:isCA(BasicConstraints);
    (\+std:isCA(BasicConstraints), \+member(ExtKeyUsage, oCSPSigning))
  ).

checkExtendedKeyUsage(_, ExtKeyUsage) :-
  ExtKeyUsage = [].

checkKeyCertSign(KeyUsage) :-
  KeyUsage = []; member(keyCertSign, KeyUsage).


validSHA1(Algorithm) :-
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
  firefox_env:domain(D),
  std:nameMatchesCN(D, Subject).

% in seconds
duration27MonthsPlusSlop(71712000).

isNSSTimeValid(CertPolicies, _, _, RootSubject):-
  \+std:isEV(CertPolicies, RootSubject).

isNSSTimeValid(CertPolicies, Lower, Upper, RootSubject):-
  std:isEV(CertPolicies, RootSubject),
  duration27MonthsPlusSlop(ValidDuration),
  Upper - Lower #< ValidDuration.

notcrl(F):-
    var(F), F = "".

notcrl(F):-
    nonvar(F), \+firefox_env:onecrl(F).

verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage):-
  firefox_env:trusted_roots(Fingerprint),
  \+firefox_env:symantecFingerprint(Fingerprint),
  std:isTimeValid(Lower, Upper),
  nssNameConstraintValid(LeafSANList, Fingerprint),
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage).

verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):- 
  types:sANList(SANList),
  types:timestamp(Lower),
  types:timestamp(Upper),
  types:algorithm(Algorithm),
  types:basicConstraints(BasicConstraints),
  types:keyUsageList(KeyUsage),
  types:extKeyUsageList(ExtKeyUsage),
  types:certificatePolicy(CertPolicies),
  types:stapledResponse(StapledResponse),
  types:ocspResponse(OcspResponse),
  types:timestamp(RootLower),
  types:timestamp(RootUpper),
  types:basicConstraints(RootBasicConstraints),
  types:keyUsageList(RootKeyUsage),
  notcrl(Fingerprint),
  firefoxNameMatches(SANList, Subject),
  std:isTimeValid(Lower, Upper),
  validSHA1(Algorithm),
  \+std:isCA(BasicConstraints),
  checkKeyUsage(BasicConstraints, KeyUsage),
  checkExtendedKeyUsage(BasicConstraints, ExtKeyUsage),
  notRevoked(Lower, Upper, CertPolicies, RootSubject, StapledResponse, OcspResponse),
  isNSSTimeValid(CertPolicies, Lower, Upper, RootSubject),
  verifiedRoot(SANList, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).