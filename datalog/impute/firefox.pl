:- module(firefox, [
  verified_firefox/19
]).

:- use_module(env).
:- use_module(std).
:- use_module(onecrl).
:- use_module(ev).
:- use_module(library(clpfd)).

symantecFingerprint("FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A").
symantecFingerprint("5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766").
symantecFingerprint("B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4").
symantecFingerprint("37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C").
symantecFingerprint("A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912").
symantecFingerprint("A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B").
symantecFingerprint("363F3C849EAB03B0A2A0F636D7B86D04D3AC7FCFE26A0A9121AB9795F6E176DF").
symantecFingerprint("9D190B2E314566685BE8A889E27AA8C7D7AE1D8AADDBA3C1ECF9D24863CD34B9").
symantecFingerprint("FE863D0822FE7A2353FA484D5924E875656D3DC9FB58771F6F616F9D571BC592").
symantecFingerprint("CB627D18B58AD56DDE331A30456BC65C601A4E9B18DEDCEA08E7DAAA07815FF0").
symantecFingerprint("8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F").
symantecFingerprint("A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557").
symantecFingerprint("4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C").
symantecFingerprint("CBB5AF185E942A2402F9EACBC0ED5BB876EEA3C1223623D00447E4F3BA554B65").
symantecFingerprint("92A9D9833FE1944DB366E8BFAE7A95B6480C2D6C6C2A1BE65D4236B608FCA1BB").
symantecFingerprint("EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244").
symantecFingerprint("69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79").
symantecFingerprint("9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF").
symantecFingerprint("2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C").

tubitak1Fingerprint("46EDC3689046D53A453FB3104AB80DCAEC658B2660EA1629DD7E867990648716").
tubitak1Subtree("*.gov.tr").
tubitak1Subtree("*.k12.tr").
tubitak1Subtree("*.pol.tr").
tubitak1Subtree("*.mil.tr").
tubitak1Subtree("*.tsk.tr").
tubitak1Subtree("*.kep.tr").
tubitak1Subtree("*.bel.tr").
tubitak1Subtree("*.edu.tr").
tubitak1Subtree("*.org.tr").

anssiFingerprint("B9BEA7860A962EA3611DAB97AB6DA3E21C1068B97D55575ED0E11279C11C8932").
anssiSubtree("*.fr").
anssiSubtree("*.gp").
anssiSubtree("*.gf").
anssiSubtree("*.mq").
anssiSubtree("*.re").
anssiSubtree("*.yt").
anssiSubtree("*.pm").
anssiSubtree("*.bl").
anssiSubtree("*.mf").
anssiSubtree("*.wf").
anssiSubtree("*.pf").
anssiSubtree("*.nc").
anssiSubtree("*.tf").

% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
nssNameConstraintValid(_, RootFingerprint) :-
  env:trusted_roots(RootFingerprint),
  \+anssiFingerprint(RootFingerprint),
  \+tubitak1Fingerprint(RootFingerprint).

nssNameConstraintValid(LeafSANList, RootFingerprint) :-
  tubitak1Fingerprint(RootFingerprint),
  tubitak1Subtree(Tree),
  member(Name, LeafSANList),
  std:stringMatch(Tree, Name).

nssNameConstraintValid(LeafSANList, RootFingerprint) :-
  anssiFingerprint(RootFingerprint),
  anssiSubtree(Tree),
  member(Name, LeafSANList),
  std:stringMatch(Tree, Name).

% revocation_response = [valid, expired, verified, status]

notRevoked(Lower, Upper, CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  shortLived(Lower, Upper);
  notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse).

stapledResponse(Response):-
  Response = [A, B, C, D],
  (A = 0; A = 1),
  (B = 0; B = 1),
  (C = 0; C = 1),
  (D = 0; D = 1).

ocspResponse(Response):-
  Response = [A, B, C, D],
  (A = 0; A = 1),
  (B = 0; B = 1),
  (C = 0; C = 1),
  (D = revoked; D = notknown).


% stapledResponseError(StapledResponse) :-
%   stapledResponse(StapledResponse),
%   (
%     StapledResponse = [0, _, _, _];
%     StapledResponse = [_, 1, _, _];
%     StapledResponse = [_, _, 0, _]
%   ).

% ocspResponseError(OcspResponse):-
%   ocspResponse(OcspResponse),
%   (
%     OcspResponse = [0, _, _, _];
%     OcspResponse = [_, 1, _, _];
%     OcspResponse = [_, _, 0, _]
%   ).

% ocspRevoked(_, _, _, OcspResponse) :-
%   OcspResponse = [1, 0, 1, revoked];
%   OcspResponse = [1, 0, 1, notknown].

% ocspRevoked(_, _, StapledResponse, OcspResponse) :-
%   (OcspResponse = [], stapledResponseError(StapledResponse));
%   (ocspResponseError(OcspResponse), stapledResponseError(StapledResponse)).

% ocspRevoked(CertPolicies, RootSubject, _, OcspResponse) :-
%   ev:isEV(CertPolicies, RootSubject),
%   (OcspResponse = []; ocspResponseError(OcspResponse)).


notOCSPRevoked(_, _, _, OcspResponse) :-
  OcspResponse = [].

notOCSPRevoked(_, _, _, OcspResponse) :-
  OcspResponse = [1, 0, 1, good].

notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  ev:isDV(CertPolicies, RootSubject),
  StapledResponse = [],
  ocspResponse(OcspResponse),
  (
    OcspResponse = [0, _, _, _];
    OcspResponse = [_, _, 0, _];
    OcspResponse = [_, 1, _, _]
  ).

notOCSPRevoked(CertPolicies, RootSubject, StapledResponse, OcspResponse) :-
  ev:isDV(CertPolicies, RootSubject),
  stapledResponse(StapledResponse),
  StapledResponse = [1, 0, 1, _],
  ocspResponse(OcspResponse),
  (
    OcspResponse = [0, _, _, _];
    OcspResponse = [_, 1, _, _];
    OcspResponse = [_, _, 0, _]
  ).


tenDaysInSeconds(864001).

shortLived(Lower, Upper) :-
  tenDaysInSeconds(ValidDuration),
  Upper - Lower #< ValidDuration.

checkKeyUsage(_, KeyUsage) :-
  KeyUsage = [].

checkKeyUsage(BasicConstraints, KeyUsage) :-
  std:isCA(BasicConstraints),
  member("keyCertSign", KeyUsage).

checkKeyUsage(BasicConstraints, KeyUsage) :-
  std:isNotCA(BasicConstraints),
  (
    member("digitalSignature", KeyUsage);
    member("keyEncipherment", KeyUsage);
    member("keyAgreement", KeyUsage)
  ).

checkExtendedKeyUsage(BasicConstraints, ExtKeyUsage) :-
  std:isCA(BasicConstraints),
  std:extendedKeyUsageExpected(ExtKeyUsage, "serverAuth", 1).

checkExtendedKeyUsage(BasicConstraints, ExtKeyUsage) :-
  std:isNotCA(BasicConstraints),
  std:extendedKeyUsageExpected(ExtKeyUsage, "OCSPSigning", 0),
  std:extendedKeyUsageExpected(ExtKeyUsage, "serverAuth", 1).

checkExtendedKeyUsage(_, ExtKeyUsage) :-
  ExtKeyUsage = [].


checkKeyCertSign(KeyUsage) :-
  KeyUsage = [];
  member("keyCertSign", KeyUsage).


validSHA1(Algorithm) :-
  std:algorithm(Algorithm),
  % ecdsa with sha1
  Algorithm \== "1.2.840.10045.4.1",
  % rsa signature with sha1
  Algorithm \== "1.3.14.3.2.29",
  % rsa encryption with sha1
  Algorithm \== "1.2.840.113549.1.1.5".


firefoxNameMatches(SANList, _):-
  std:nameMatchesSAN(SANList).

% Check CN ONLY if SAN not present
firefoxNameMatches(SANList, Subject) :-
  SANList = [],
  std:nameMatchesCN(Subject).

% in seconds
duration27MonthsPlusSlop(71712000).

isNSSTimeValid(CertPolicies, _, _, RootSubject):-
  \+ev:isEV(CertPolicies, RootSubject).

isNSSTimeValid(CertPolicies, Lower, Upper, RootSubject):-
  ev:isEV(CertPolicies, RootSubject),
  duration27MonthsPlusSlop(ValidDuration),
  ValidDuration #>= Upper - Lower.

verifiedRoot(LeafSANList, Fingerprint, Lower, Upper, BasicConstraints, KeyUsage):-
  std:isRoot(Fingerprint),
  \+symantecFingerprint(Fingerprint),
  std:isTimeValid(Lower, Upper),
  nssNameConstraintValid(LeafSANList, Fingerprint),
  std:isCA(BasicConstraints),
  checkKeyCertSign(KeyUsage).

verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):- 
  onecrl:notcrl(Fingerprint),
  firefoxNameMatches(SANList, Subject),
  std:isTimeValid(Lower, Upper),
  validSHA1(Algorithm),
  std:isNotCA(BasicConstraints),
  checkKeyUsage(BasicConstraints, KeyUsage),
  checkExtendedKeyUsage(BasicConstraints, ExtKeyUsage),
  notRevoked(Lower, Upper, CertPolicies, RootSubject, StapledResponse, OcspResponse),
  isNSSTimeValid(CertPolicies, Lower, Upper, RootSubject),
  verifiedRoot(SANList, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).