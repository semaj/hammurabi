#!/usr/bin/env swipl

:- module(chrome, [
  verifiedLeaf/8
]).

:- use_module(library(uri)).
:- use_module(chrome_env).
:- use_module(std).
:- use_module(psl).

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

suffixMatch(["*"|[]], _).
suffixMatch([NameLabel|NameRest], [SuffixLabel|SuffixRest]) :-
  NameLabel = SuffixLabel,
  suffixMatch(NameRest, SuffixRest).

isPublicSuffix(NameLabels) :-
  reverse(NameLabels, NameLabelsReverse),
  publicSuffix(Suffix),
  split_string(Suffix, ".", "", SuffixLabels),
  reverse(SuffixLabels, SuffixLabelsReverse),
  suffixMatch(NameLabelsReverse, SuffixLabelsReverse).

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
  NameLabelsLength > 2,
  \+ isPublicSuffix(NameLabels).

cleanName(Name, Decoded) :-
  uri_encoded(path, D, Name),
  atom_string(D, Decoded),
  sub_string(Decoded, _, 1, 0, LastChar),
  LastChar \= ".".

cleanName(Name, Cleaned) :-
  uri_encoded(path, D, Name),
  atom_string(D, Decoded),
  sub_string(Decoded, _, 1, 0, LastChar),
  LastChar = ".",
  sub_string(Decoded, 0, _, 1, Cleaned).

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
        cleanName(PermittedName, CleanPermittedName),
        nameConstraintValid(CleanPermittedName)
      )),
      member(PermittedName, PermittedNames),
      cleanName(PermittedName, CleanPermittedName),
      namePermitted(Name, CleanPermittedName)
    );
    PermittedNamesLength = 0
  ),
  forall(member(ExcludedName, ExcludedNames), (
    cleanName(ExcludedName, CleanExcludedName),
    nameConstraintValid(CleanExcludedName),
    nameNotExcluded(Name, CleanExcludedName)
  )).

% Name-constrained SAN list
dnsNameConstrained(_, ChildSANList, PermittedNames, ExcludedNames) :-
  forall(member(Name, ChildSANList), dnsNameValid(Name,  PermittedNames, ExcludedNames)).

% For certificates issued on-or-after the BR effective
% For certificates issued on-or-after 1 April 2015 (39 months)
% For certificates issued on-or-after 1 March 2018 (825 days)
% For certificates issued on-or-after 1 September 2020 (398 days)
% net/cert/cert_verify_proc
leafDurationValid(Lower, Upper):-
  Duration = Upper - Lower,
  July2012 = 1341100800,
  April2015 = 1427846400,
  March2018 = 1519862400,
  July2019 = 1561939200,
  Sep2020 = 1598918400,
  TenYears = 315532800,
  SixtyMonths = 157852800,
  ThirtyNineMonths = 102643200,
  EightTwentyFiveDays = 71280000,
  ThreeNinetyEightDays = 34387200,
  (
    (Lower < July2012, Upper < July2019, Duration =< TenYears);
    (Lower >= July2012, Lower < April2015, Duration =< SixtyMonths);
    (Lower >= April2015, Lower < March2018, Duration =< ThirtyNineMonths);
    (Lower >= March2018, Lower < Sep2020, Duration =< EightTwentyFiveDays);
    (Lower >= Sep2020, Duration =< ThreeNinetyEightDays)
  ).

fingerprintValid(Fingerprint, _):-
  chrome_env:trusted(Fingerprint),
  \+chrome_env:anssiFingerprint(Fingerprint),
  \+chrome_env:indiaFingerprint(Fingerprint).

fingerprintValid(Fingerprint, Domain):-
  chrome_env:indiaFingerprint(Fingerprint),
  chrome_env:indiaDomain(Accepted),
  std:stringMatch(Accepted, Domain).

fingerprintValid(Fingerprint, Domain):-
  chrome_env:anssiFingerprint(Fingerprint),
  chrome_env:anssiDomain(Accepted),
  std:stringMatch(Accepted, Domain).

strongSignature(Algorithm):-
  % ECDSA + SHA512
  Algorithm = "1.2.840.10045.4.3.2";
  % ECDSA + SHA384
  Algorithm = "1.2.840.10045.4.3.3";
  % ECDSA + SHA512
  Algorithm = "1.2.840.10045.4.3.4";
  % RSA + SHA256
  Algorithm = "1.2.840.113549.1.1.11";
  % RSA + SHA384
  Algorithm = "1.2.840.113549.1.1.12";
  % RSA + SHA512
  Algorithm = "1.2.840.113549.1.1.13";
  % RSA-PSS + SHA256 -- Firefox does not allow this one (yet).
  Algorithm = "1.2.840.113549.1.1.10".

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
  ),
  % Firefox does not have this exclusion.
  \+member(keyCertSign, KeyUsage).

checkKeyCertSign(KeyUsage) :-
  KeyUsage = []; 
  member(keyCertSign, KeyUsage).

extKeyUsageValid(ExtKeyUsage) :-
  ExtKeyUsage = []; 
  % I'm pretty sure about this one, firefox doesn't allow this
  member(any, ExtKeyUsage);
  member(serverAuth, ExtKeyUsage).

symantecUntrusted(Lower):-
  June2016 = 1464739200,
  Dec2017 = 1512086400,
  (Lower < June2016; Lower > Dec2017).

% if legacy symantec and
% symantec enforcement on OR untrusted symantec
% legacy: if it's a symantec root and not an exception/managed
% untrusted: issued after 01 dec 2017 or before 01 jun 2016
badSymantec(Fingerprint, Lower):-
  chrome_env:trusted(Fingerprint),
  chrome_env:symantecRoot(Fingerprint),
  \+chrome_env:symantecException(Fingerprint),
  \+chrome_env:symantecManagedCA(Fingerprint),
  symantecUntrusted(Lower).

isChromeRoot(Fingerprint):-
  chrome_env:trusted(Fingerprint),
  certs:envDomain(Domain),
  fingerprintValid(Fingerprint, Domain).

isValidPKI(Cert) :-
  certs:spkiDSAParameters(Cert, na, na, na),
  certs:spkiRSAModLength(Cert, na).

isValidPKI(Cert) :-
  certs:spkiDSAParameters(Cert, Length, _, _),
  Length \= na,
  Length >= 1024.

isValidPKI(Cert) :-
  certs:spkiRSAModLength(Cert, Length),
  Length \= na,
  Length >= 1024.

notCrlSet(F):-
    var(F), F = "".

notCrlSet(F):-
    nonvar(F), \+chrome_env:crlSet(F).

pathLengthValid(_, BasicConstraints):-
  BasicConstraints = [_, Limit],
  Limit == none.

pathLengthValid(CertsSoFar, BasicConstraints):-
  BasicConstraints = [_, Limit],
  Limit \= none, CertsSoFar =< Limit.

verifiedRoot(Fingerprint, Lower, Upper, BasicConstraints, KeyUsage, ExtKeyUsage):-
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage),
  std:isTimeValid(Lower, Upper),
  isChromeRoot(Fingerprint),
  \+badSymantec(Fingerprint, Lower),
  std:isCA(BasicConstraints),
  % Trust anchor WITH CONSTRAINTS
  extKeyUsageValid(ExtKeyUsage).

verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage):-
  std:isCA(BasicConstraints),
  notCrlSet(Fingerprint),
  \+badSymantec(Fingerprint, Lower),
  std:isTimeValid(Lower, Upper),
  strongSignature(Algorithm),
  keyUsageValid(BasicConstraints, KeyUsage),
  extKeyUsageValid(ExtKeyUsage).

verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage):-
  certs:envDomain(Domain),
  std:nameMatchesSAN(Domain, SANList),
  std:isTimeValid(Lower, Upper),
  leafDurationValid(Lower, Upper),
  notCrlSet(Fingerprint),
  strongSignature(Algorithm),
  keyUsageValid(BasicConstraints, KeyUsage),
  extKeyUsageValid(ExtKeyUsage).

certVerifiedNonLeaf(Cert, LeafSANList, CertsSoFar):-
  isValidPKI(Cert),
  % Firefox does not have this restriction
  certs:version(Cert, 2),
  certs:fingerprint(Cert, Fingerprint),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  std:getBasicConstraints(Cert, BasicConstraints),
  certs:signatureAlgorithm(Cert, OuterAlgorithm, OuterParams),
  certs:signature(Cert, InnerAlgorithm, InnerParams),
  OuterAlgorithm = InnerAlgorithm,
  OuterParams = InnerParams,
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  pathLengthValid(CertsSoFar, BasicConstraints),
  (
    (
      verifiedIntermediate(Fingerprint, Lower, Upper, InnerAlgorithm, BasicConstraints, KeyUsage, ExtKeyUsage),
      certs:issuer(Cert, Parent),
      Cert \= Parent,
      certVerifiedNonLeaf(Parent, LeafSANList, CertsSoFar + 1),
      (
        (
          certs:nameConstraintsExt(Cert, true),
          findall(PermittedName, certs:nameConstraintsPermitted(Cert, "DNS", PermittedName), Permitted),
          findall(ExcludedName, certs:nameConstraintsExcluded(Cert, "DNS", ExcludedName), Excluded),
          dnsNameConstrained(_, LeafSANList, Permitted, Excluded)
        );
        certs:nameConstraintsExt(Cert, false)
      )
    );
    verifiedRoot(Fingerprint, Lower, Upper, BasicConstraints, KeyUsage, ExtKeyUsage)
  ).

% TODO
isNotRevoked(_).

certVerifiedLeaf(Cert, SANList):-
  % Firefox does not have this restriction

  ( certs:pathLimit(Cert, none); certs:basicConstraintsExt(Cert, false) ),
  %std:getEVStatus(Cert, EVStatus),
  %(
    %EVStatus = not_ev;
    %isNotRevoked(Cert)
  %),
  certs:fingerprint(Cert, Fingerprint),
  % Firefox does not have this restriction
  certs:version(Cert, 2),
  length(SANList, SANListLength),
  SANListLength > 0,
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  forall(member(SAN, SANList), nameValid(SAN)),
  certs:signatureAlgorithm(Cert, OuterAlgorithm, OuterParams),
  certs:signature(Cert, InnerAlgorithm, InnerParams),
  OuterAlgorithm = InnerAlgorithm,
  OuterParams = InnerParams,
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  isValidPKI(Cert),
  verifiedLeaf(Fingerprint, SANList, Lower, Upper, InnerAlgorithm, BasicConstraints, KeyUsage, ExtKeyUsage).

certVerifiedChain(Cert):-
  findall(Name, certs:san(Cert, Name), SANList),
  maplist(cleanName, SANList, CleanSANList),
  certVerifiedLeaf(Cert, CleanSANList),
  certs:issuer(Cert, Parent),
  certVerifiedNonLeaf(Parent, CleanSANList, 0).

main([CertsFile, Cert]):-
  statistics(walltime, _),
  consult(CertsFile),
  %statistics(walltime, [_ | [LoadTime]]),
  %write('Cert facts loading time: '), write(LoadTime), write('ms\n'),
  statistics(walltime, _),
  certVerifiedChain(Cert).
  %statistics(walltime, [_ | [VerifyTime]]).
  %write('Cert verification time: '), write(VerifyTime), write('ms\n').
  
