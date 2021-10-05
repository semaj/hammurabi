#!/usr/bin/env swipl
:- module(firefox, [
  verifiedLeaf/12
]).

:- use_module(ev).
:- use_module(firefox_env).
:- use_module(std).

:- initialization(main, main).

% Presented: example.com, Excluded: .example.com -- valid
nameLabelsNotExcluded([], [""|[]]).
% Presented: example.org, Excluded: example.com -- valid
% Presented: example.com, Excluded: example.com -- invalid
nameLabelsNotExcluded([NameLabel|_], [ExcludedLabel|_]) :-
  ExcludedLabel \= "",
  NameLabel \= ExcludedLabel.
% Presented: example1.com, Excluded: example.com -- valid
nameLabelsNotExcluded([NameLabel|NameRest], [ExcludedLabel|ExcludedRest]) :-
  NameLabel = ExcludedLabel,
  nameLabelsNotExcluded(NameRest, ExcludedRest).

% Nothing is excluded
nameNotExcluded(_, "").
% Something is excluded
nameNotExcluded(Name, Excluded) :-
  % Split into labels
  split_string(Name, ".", "", NameLabels),
  split_string(Excluded, ".", "", ExcludedLabels),
  % Walk the labels from the end to the front
  reverse(NameLabels, NameLabelsReversed),
  reverse(ExcludedLabels, ExcludedLabelsReversed),
  nameLabelsNotExcluded(NameLabelsReversed, ExcludedLabelsReversed).

% There's nothing (more) to permit -- valid
nameLabelsPermitted(_, []).
% Presented: foo.example.com, Permitted: .example.com -- valid
% Presented: example.com, Permitted: .example.com -- invalid
nameLabelsPermitted([_|_], [""|[]]).
% Presented: foo.example.com, Permitted: foo.example.com -- valid
% Presented: foo1.example.com, Permitted: foo.example.com --invalid
nameLabelsPermitted([NameLabel|NameRest], [PermittedLabel|PermittedRest]) :- 
  PermittedLabel \= "", % Should be checked earlier
  PermittedLabel = NameLabel,
  nameLabelsPermitted(NameRest, PermittedRest).

% Everything is permitted
namePermitted(_, "").
% Not eveything is permitted
namePermitted(Name, Permitted) :-
  split_string(Name, ".", "", NameLabels),
  split_string(Permitted, ".", "", PermittedLabels),
  reverse(NameLabels, NameLabelsReversed),
  reverse(PermittedLabels, PermittedLabelsReversed),
  nameLabelsPermitted(NameLabelsReversed, PermittedLabelsReversed).

% DNS name constraint name validity
nameConstraintValid(Name) :-
  string_chars(Name, NameChars),
  std:count(NameChars, '*', 0),
  sub_string(Name, _, 1, 0, LastChar),
  LastChar \= ".".

% SAN/CN name validity, without wildcard
nameValid(Name) :-
  string_chars(Name, NameChars),
  std:count(NameChars, '*', 0),
  sub_string(Name, 0, 1, _, FirstChar),
  FirstChar \= ".",
  sub_string(Name, _, 1, 0, LastChar),
  LastChar \= ".".

% SAN/CN name validity, with wildcard
nameValid(Name) :-
  string_chars(Name, NameChars),
  % If there is (max) one wildcard, it must be first label
  std:count(NameChars, '*', 1),
  sub_string(Name, 0, 1, _, FirstChar),
  FirstChar = "*",
  sub_string(Name, _, 1, 0, LastChar),
  LastChar \= ".",
  % If there is a wildcard, there must be at least two labels
  % (other than the wildcard label)
  split_string(Name, ".", "", NameLabels),
  length(NameLabels, NameLabelsLength),
  NameLabelsLength > 2.

% Name-constrained name (any)
dnsNameValid(Name, PermittedNames, ExcludedNames) :-
  length(PermittedNames, PermittedNamesLength),
  length(ExcludedNames, ExcludedNamesLength),
  % RFC 5280 says both cannot be empty
  ( PermittedNamesLength > 0; ExcludedNamesLength > 0),
  (
    (
      PermittedNamesLength > 0,
      forall(member(PermittedName, PermittedNames), (
        nameConstraintValid(PermittedName)
      )),
      member(PermittedName, PermittedNames),
      namePermitted(Name, PermittedName)
    );
    PermittedNamesLength = 0
  ),
  forall(member(ExcludedName, ExcludedNames), (
    nameConstraintValid(ExcludedName),
    nameNotExcluded(Name, ExcludedName)
  )).

% Name-constrained Common Name
dnsNameConstrained(ChildCommonName, ChildSANList, PermittedNames, ExcludedNames) :-
  ChildSANList = [],
  dnsNameValid(ChildCommonName, PermittedNames, ExcludedNames).

% Name-constrained SAN list
dnsNameConstrained(_, ChildSANList, PermittedNames, ExcludedNames) :-
  ChildSANList \= [],
  forall(member(Name, ChildSANList), dnsNameValid(Name,  PermittedNames, ExcludedNames)).

% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
internationalValid(_, RootFingerprint) :-
  firefox_env:trustedRoots(RootFingerprint),
  \+firefox_env:anssiFingerprint(RootFingerprint),
  \+firefox_env:tubitak1Fingerprint(RootFingerprint).

internationalValid(LeafSANList, RootFingerprint) :-
  firefox_env:tubitak1Fingerprint(RootFingerprint),
  firefox_env:tubitak1Subtree(Tree),
  member(Name, LeafSANList),
  std:stringMatch(Tree, Name).

internationalValid(LeafSANList, RootFingerprint) :-
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
  Upper - Lower < ValidDuration.

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

% Firefox rejects end-entity certificates 
% (other than delegated OCSP Signing Certs)
% that have the oCSPSigning EKU
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
  certs:envDomain(D),
  std:nameMatchesSAN(D, SANList).

% Check CN ONLY if SAN not present
firefoxNameMatches(SANList, CommonName) :-
  SANList = [],
  certs:envDomain(D),
  std:nameMatchesCN(D, CommonName).

% in seconds
duration27MonthsPlusSlop(71712000).

leafDurationValid(EVStatus, _, _):-
  EVStatus = not_ev.

leafDurationValid(EVStatus, Lower, Upper):-
  EVStatus = ev,
  duration27MonthsPlusSlop(ValidDuration),
  Upper - Lower < ValidDuration.

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
  internationalValid(LeafSANList, Fingerprint),
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage).

verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):- 
  notCrl(Fingerprint),
  std:isTimeValid(Lower, Upper),
  strongSignature(Algorithm),
  keyUsageValid(BasicConstraints, KeyUsage),
  extKeyUsageValid(BasicConstraints, ExtKeyUsage),
  notRevoked(Lower, Upper, EVStatus, StapledResponse, OcspResponse).

verifiedLeaf(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):- 
  \+std:isCA(BasicConstraints),
  firefoxNameMatches(SANList, CommonName),
  leafDurationValid(EVStatus, Lower, Upper),
  verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse).

certVerifiedNonLeaf(Cert, LeafCommonName, LeafSANList, EVStatus):-
  certs:fingerprint(Cert, Fingerprint),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  certs:stapledResponse(Cert, StapledResponse),
  certs:ocspResponse(Cert, OcspResponse),
  (
    (
      verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse), 
      certs:issuer(Cert, Parent),
      certVerifiedNonLeaf(Parent, LeafCommonName, LeafSANList, EVStatus),
      (
        (
          certs:nameConstraintsExt(Cert, true),
          findall(PermittedName, certs:nameConstraintsPermitted(Cert, "DNS", PermittedName), Permitted),
          findall(ExcludedName, certs:nameConstraintsExcluded(Cert, "DNS", ExcludedName), Excluded),
          dnsNameConstrained(LeafCommonName, LeafSANList, Permitted, Excluded)
        );
        certs:nameConstraintsExt(Cert, false)
      )
    );
    verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage)
  ).

certVerifiedLeaf(Cert, EVStatus):-
  certs:fingerprint(Cert, Fingerprint),
  findall(Name, certs:san(Cert, Name), SANList),
  length(SANList, SANListLength),
  certs:commonName(Cert, CommonName),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  (
    (
      SANListLength > 0,
      forall(member(SAN, SANList), nameValid(SAN))
    );
    (
      SANListLength = 0,
      nameValid(CommonName)
    )
  ),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  certs:stapledResponse(Cert, StapledResponse),
  certs:ocspResponse(Cert, OcspResponse),
  verifiedLeaf(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse).

certVerifiedChain(Cert):-
  getEVStatus(Cert, EVStatus),
  certVerifiedLeaf(Cert, EVStatus),
  findall(Name, certs:san(Cert, Name), SANList),
  certs:commonName(Cert, CommonName),
  certs:issuer(Cert, Parent),
  certVerifiedNonLeaf(Parent, CommonName, SANList, EVStatus).

main([CertsFile, Cert]):-
  statistics(walltime, _),
  consult(CertsFile),
  statistics(walltime, [_ | [LoadTime]]),
  write('Cert facts loading time: '), write(LoadTime), write('ms\n'),
  statistics(walltime, _),
  certVerifiedChain(Cert),
  statistics(walltime, [_ | [VerifyTime]]),
  write('Cert verification time: '), write(VerifyTime), write('ms\n').
