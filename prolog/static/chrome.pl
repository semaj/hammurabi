#!/usr/bin/env swipl

:- module(chrome, [
  verifiedLeaf/8
]).

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

cleanName(Name, Name) :-
  sub_string(Name, _, 1, 0, LastChar),
  LastChar \= "." .

cleanName(Name, Cleaned) :-
  sub_string(Name, _, 1, 0, LastChar),
  LastChar = ".",
  sub_string(Name, 0, _, 1, Cleaned).

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
      namePermitted(Name, PermittedName)
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

nameConstraintValid(Fingerprint, _):-
  chrome_env:trusted(Fingerprint),
  \+chrome_env:anssiFingerprint(Fingerprint),
  \+chrome_env:indiaFingerprint(Fingerprint).

nameConstraintValid(Fingerprint, Domain):-
  chrome_env:indiaFingerprint(Fingerprint),
  chrome_env:indiaDomain(Accepted),
  std:stringMatch(Accepted, Domain).

nameConstraintValid(Fingerprint, Domain):-
  chrome_env:anssiFingerprint(Fingerprint),
  chrome_env:anssiDomain(Accepted),
  std:stringMatch(Accepted, Domain).

strongSignature(Algorithm):-
  \+std:md2_sig_algo(Algorithm),
  \+std:md4_sig_algo(Algorithm),
  \+std:md5_sig_algo(Algorithm).

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
  \+member(keyCertSign, KeyUsage).

checkKeyCertSign(KeyUsage) :-
  (KeyUsage = []; member(keyCertSign, KeyUsage)).

extKeyUsageValid(ExtKeyUsage) :-
  (ExtKeyUsage = []; member(serverAuth, ExtKeyUsage)).

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
  nameConstraintValid(Fingerprint, Domain).

notCrlSet(F):-
    var(F), F = "".

notCrlSet(F):-
    nonvar(F), \+chrome_env:crlSet(F).

verifiedRoot(Fingerprint, Lower, Upper, BasicConstraints, KeyUsage):-
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage),
  std:isTimeValid(Lower, Upper),
  isChromeRoot(Fingerprint),
  \+badSymantec(Fingerprint, Lower).

verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage):-
  notCrlSet(Fingerprint),
  \+badSymantec(Fingerprint, Lower),
  std:isTimeValid(Lower, Upper),
  strongSignature(Algorithm),
  keyUsageValid(BasicConstraints, KeyUsage),
  extKeyUsageValid(ExtKeyUsage).

verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage):-
  certs:envDomain(Domain),
  std:nameMatchesSAN(Domain, SANList),
  leafDurationValid(Lower, Upper),
  verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage).

certVerifiedNonLeaf(Cert):-
  certs:fingerprint(Cert, Fingerprint),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  (
    (
      verifiedIntermediate(Fingerprint, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage),
      certs:issuer(Cert, Parent),
      certVerifiedNonLeaf(Parent),
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
    verifiedRoot(Fingerprint, Lower, Upper, BasicConstraints, KeyUsage)
  ).

certVerifiedLeaf(Cert):-
  certs:fingerprint(Cert, Fingerprint),
  findall(Name, certs:san(Cert, Name), SANList),
  length(SANList, SANListLength),
  SANListLength > 0,
  maplist(cleanName, SANList, CleanSANList),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  forall(member(SAN, CleanSANList), nameValid(SAN)),
  certs:signatureAlgorithm(Cert, Algorithm),
  std:getBasicConstraints(Cert, BasicConstraints),
  findall(Usage, certs:keyUsage(Cert, Usage), KeyUsage),
  findall(ExtUsage, certs:extendedKeyUsage(Cert, ExtUsage), ExtKeyUsage),
  verifiedLeaf(Fingerprint, CleanSANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage).

certVerifiedChain(Cert):-
  certVerifiedLeaf(Cert),
  certs:issuer(Cert, Parent),
  certVerifiedNonLeaf(Parent).

main([CertsFile, Cert]):-
  statistics(walltime, _),
  consult(CertsFile),
  statistics(walltime, [_ | [LoadTime]]),
  write('Cert facts loading time: '), write(LoadTime), write('ms\n'),
  statistics(walltime, _),
  certVerifiedChain(Cert),
  statistics(walltime, [_ | [VerifyTime]]),
  write('Cert verification time: '), write(VerifyTime), write('ms\n').
  
