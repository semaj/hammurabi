:- module(chrome, [
  certVerifiedChain/1,
  verifiedLeaf/8
]).

:- use_module(env).
:- use_module(std).
:- use_module(library(clpfd)).
:- use_module(chrome_env).
:- use_module(certs).

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
    (Lower #< July2012, Upper #< July2019, Duration #=< TenYears);
    (Lower in July2012..April2015, Duration #=< SixtyMonths);
    (Lower in April2015..March2018, Duration #=< ThirtyNineMonths);
    (Lower in March2018..Sep2020, Duration #=< EightTwentyFiveDays);
    (Lower #>= Sep2020, Duration #=< ThreeNinetyEightDays)
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
  (Lower #< June2016; Lower #> Dec2017).

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
  env:domain(Domain),
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
  env:domain(Domain),
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
      certVerifiedNonLeaf(Parent)
    );
    verifiedRoot(Fingerprint, Lower, Upper, BasicConstraints, KeyUsage)
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
  verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage).

certVerifiedChain(Cert):-
  certVerifiedLeaf(Cert),
  certs:issuer(Cert, Parent),
  certVerifiedNonLeaf(Parent).