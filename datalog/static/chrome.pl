:- module(chrome, [
  verified_chrome/13
]).

:- use_module(std).
:- use_module(library(clpfd)).
:- use_module(chrome_env).

% For certificates issued on-or-after the BR effective
% For certificates issued on-or-after 1 April 2015 (39 months)
% For certificates issued on-or-after 1 March 2018 (825 days)
% For certificates issued on-or-after 1 September 2020 (398 days)
% net/cert/cert_verify_proc
leaf_duration_valid(Lower, Upper):-
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

no_name_constraint_violation(Fingerprint, _):-
  chrome_env:trusted(Fingerprint),
  \+chrome_env:anssiFingerprint(Fingerprint),
  \+chrome_env:indiaFingerprint(Fingerprint).

no_name_constraint_violation(Fingerprint, Domain):-
  chrome_env:indiaFingerprint(Fingerprint),
  chrome_env:indiaDomain(Accepted),
  std:stringMatch(Accepted, Domain).

no_name_constraint_violation(Fingerprint, Domain):-
  chrome_env:anssiFingerprint(Fingerprint),
  chrome_env:anssiDomain(Accepted),
  std:stringMatch(Accepted, Domain).

strong_signature(Algorithm):-
  \+types:md2_sig_algo(Algorithm),
  \+types:md4_sig_algo(Algorithm),
  \+types:md5_sig_algo(Algorithm).

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
  ),
  \+member(keyCertSign, KeyUsage).

checkKeyCertSign(KeyUsage) :-
  (KeyUsage = []; member(keyCertSign, KeyUsage)).

checkExtendedKeyUsage(ExtKeyUsage) :-
  (ExtKeyUsage = []; member(serverAuth, ExtKeyUsage)).

symantec_untrusted(Lower):-
  June2016 = 1464739200,
  Dec2017 = 1512086400,
  (Lower #< June2016; Lower #> Dec2017).

% if legacy symantec and
% symantec enforcement on OR untrusted symantec
% legacy: if it's a symantec root and not an exception/managed
% untrusted: issued after 01 dec 2017 or before 01 jun 2016
bad_symantec(Fingerprint, Lower):-
  chrome_env:trusted(Fingerprint),
  chrome_env:symantec_root(Fingerprint),
  \+chrome_env:symantec_exception(Fingerprint),
  \+chrome_env:symantec_managed_ca(Fingerprint),
  symantec_untrusted(Lower).


isChromeRoot(Fingerprint):-
  chrome_env:trusted(Fingerprint),
  env:domain(Domain),
  no_name_constraint_violation(Fingerprint, Domain).

notcrl_set(F):-
    var(F), F = "".

notcrl_set(F):-
    nonvar(F), \+chrome_env:crl_set(F).

verifiedRoot(Fingerprint, Lower, Upper, BasicConstraints, KeyUsage):-
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage),
  std:isTimeValid(Lower, Upper),
  isChromeRoot(Fingerprint),
  \+bad_symantec(Fingerprint, Lower).

verified_chrome(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):- 
  notcrl_set(Fingerprint),

  types:sANList(SANList),
  env:domain(Domain),
  std:nameMatchesSAN(Domain, SANList),

  types:timestamp(Lower),
  types:timestamp(Upper),
  std:isTimeValid(Lower, Upper),
  leaf_duration_valid(Lower, Upper),

  types:algorithm(Algorithm),
  strong_signature(Algorithm),

  types:basicConstraints(BasicConstraints),
  types:keyUsageList(KeyUsage),
  checkKeyUsage(BasicConstraints, KeyUsage),

  types:extKeyUsageList(ExtKeyUsage),
  checkExtendedKeyUsage(ExtKeyUsage),

  types:timestamp(RootLower),
  types:timestamp(RootUpper),
  types:basicConstraints(RootBasicConstraints),
  types:keyUsageList(RootKeyUsage),
  
  verifiedRoot(RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).