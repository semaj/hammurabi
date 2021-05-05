:- module(firefox, [
    parent/4,
    verified/4,
    verified/1
]).
:-style_check(-singleton).

:- use_module(env).
:- use_module(certs).
:- use_module(std).
:- use_module(onecrl).
:- use_module(ext).
:- use_module(ev).
:- use_module(checks).

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

% Error reporting clause
nssNameConstraintValid(Leaf, Root) :-
  checks:nssNameConstraintCheckEnabled(false),
  std:isCert(Leaf),
  std:isCert(Root).

% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
nssNameConstraintValid(Leaf, Root) :-
  certs:fingerprint(Root, F),
  \+anssiFingerprint(F),
  \+tubitak1Fingerprint(F),
  std:isCert(Leaf).

nssNameConstraintValid(Leaf, Root) :-
  tubitak1Fingerprint(F),
  certs:fingerprint(Root, F),
  certs:extensionValues(Leaf, "SubjectAlternativeNames", Name),
  tubitak1Subtree(Tree),
  std:stringMatch(Tree, Name).

nssNameConstraintValid(Leaf, Root) :-
  anssiFingerprint(F),
  certs:fingerprint(Root, F),
  certs:extensionValues(Leaf, "SubjectAlternativeNames", Name),
  anssiSubtree(Tree),
  std:stringMatch(Tree, Name).

% Error reporting clause
notRevoked(Cert) :-
  checks:revokedCheckEnabled(false),
  std:isCert(Cert).

notRevoked(Cert) :-
  shortLived(Cert). % Firefox uses 10 days

notRevoked(Cert) :-
  std:isCert(Cert),
  \+ocspRevoked(Cert).

stapledResponseError(Cert) :-
  certs:stapled_ocsp_response_invalid(Cert).

stapledResponseError(Cert) :-
  certs:stapled_ocsp_response_expired(Cert).

stapledResponseError(Cert) :-
  certs:stapled_ocsp_response_not_verified(Cert).

ocspResponseError(Cert) :-
  certs:ocsp_response_expired(Cert, R).

ocspResponseError(Cert) :-
  certs:ocsp_response_invalid(Cert, R).

ocspResponseError(Cert) :-
  certs:ocsp_response_not_verified(Cert, R).

ocspRevoked(Cert) :-
  certs:ocsp_response_valid(Cert, Responder),
  certs:ocsp_response_verified(Cert, Responder),
  certs:ocsp_response_not_expired(Cert, Responder),
  certs:ocsp_status_revoked(Cert, Responder).

ocspRevoked(Cert) :-
  certs:ocsp_response_valid(Cert, Responder),
  certs:ocsp_response_verified(Cert, Responder),
  certs:ocsp_response_not_expired(Cert, Responder),
  certs:ocsp_status_unknown(Cert, Responder).

ocspRevoked(Cert) :-
  certs:no_ocsp_responders(Cert),
  stapledResponseError(Cert).

ocspRevoked(Cert) :-
  ev:isEV(Cert),
  certs:no_ocsp_responders(Cert).

ocspRevoked(Cert) :-
  ocspResponseError(Cert),
  stapledResponseError(Cert).

ocspRevoked(Cert) :-
  ev:isEV(Cert),
  ocspResponseError(Cert).

tenDaysInSeconds(864001).

shortLived(Cert) :-
  tenDaysInSeconds(ValidDuration),
  validity(Cert, Lower, Upper),
  ext:subtract(Duration, Upper, Lower),
  ext:larger(ValidDuration, Duration).

notInOneCRL(Cert) :-
  certs:fingerprint(Cert, Fingerprint),
  \+onecrl:onecrl(Fingerprint).

notOCSPRevokedCheck(Cert) :-
  certs:no_ocsp_responders(Cert).


notOCSPRevokedCheck(Cert) :-
  certs:ocsp_response_valid(Cert, Responder),
  certs:ocsp_response_verified(Cert, Responder),
  certs:ocsp_response_not_expired(Cert, Responder),
  certs:ocsp_status_good(Cert, Responder).

notOCSPRevokedCheck(Cert) :-
  \+ev:isEV(Cert),
  certs:no_stapled_ocsp_response(Cert),
  certs:ocsp_response_invalid(Cert, R).


notOCSPRevokedCheck(Cert) :-
  \+ev:isEV(Cert),
  certs:no_stapled_ocsp_response(Cert),
  certs:ocsp_response_not_verified(Cert, R).


notOCSPRevokedCheck(Cert) :-
  \+ev:isEV(Cert),
  certs:no_stapled_ocsp_response(Cert),
  certs:ocsp_response_expired(Cert, R).

notOCSPRevokedCheck(Cert) :-
  \+ev:isEV(Cert),
  certs:stapled_ocsp_response_valid(Cert),
  certs:stapled_ocsp_response_verified(Cert),
  certs:stapled_ocsp_response_not_expired(Cert),
  certs:ocsp_response_invalid(Cert, R).

notOCSPRevokedCheck(Cert) :-
  \+ev:isEV(Cert),
  certs:stapled_ocsp_response_valid(Cert),
  certs:stapled_ocsp_response_verified(Cert),
  certs:stapled_ocsp_response_not_expired(Cert),
  certs:ocsp_response_not_verified(Cert, R).


notOCSPRevokedCheck(Cert) :-
  \+ev:isEV(Cert),
  certs:stapled_ocsp_response_valid(Cert),
  certs:stapled_ocsp_response_verified(Cert),
  certs:stapled_ocsp_response_not_expired(Cert),
  certs:ocsp_response_expired(Cert, R).

checkKeyUsage(Cert) :-
  std:isCA(Cert),
  certs:extensionExists(Cert, "KeyUsage", true),
  std:usageAllowed(Cert, "keyCertSign").

checkKeyUsage(Cert) :-
  certs:extensionExists(Cert, "KeyUsage", false).

checkKeyUsage(Cert) :-
  \+std:isCA(Cert),
  std:usageAllowed(Cert, "digitalSignature").

checkKeyUsage(Cert) :-
  \+std:isCA(Cert),
  std:usageAllowed(Cert, "keyEncipherment").

checkKeyUsage(Cert) :-
  \+std:isCA(Cert),
  std:usageAllowed(Cert, "keyAgreement").


notSymantec(Cert) :-
  certs:fingerprint(Cert, F),
  \+symantecFingerprint(F).

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

validSHA1(Cert) :-
  certs:signatureAlgorithm(Cert, Algorithm),
  % ecdsa with sha1
  ext:unequal(Algorithm, "1.2.840.10045.4.1"),
  % rsa signature with sha1
  ext:unequal(Algorithm, "1.3.14.3.2.29"),
  % rsa encryption with sha1
  ext:unequal(Algorithm, "1.2.840.113549.1.1.5").

checkExtendedKeyUsage(Cert) :-
  std:isCA(Cert),
  std:extendedKeyUsageExpected(Cert, "serverAuth", true).

checkExtendedKeyUsage(Cert):-
  \+std:isCA(Cert),
  std:extendedKeyUsageExpected(Cert, "OCSPSigning", false),
  std:extendedKeyUsageExpected(Cert, "serverAuth", true).

checkExtendedKeyUsage(Cert) :-
  certs:extensionExists(Cert, "ExtendedKeyUsage", false).

% Override kb_env.pl
max_intermediates(5).

% Error reporting clause
maxIntermediatesOkay(ChainLen):-
  checks:chainLengthCheckEnabled(false),
  ext:larger(ChainLen, -1),
  ext:larger(100, ChainLen).

% Custom limit on intermediate certs check
% exempts trusted certs from limit
maxIntermediatesOkay(ChainLen):-
  max_intermediates(M),
  ext:larger(M, ChainLen).

verified(Leaf, Cert, ChainLen):-
  std:isTimeValid(Cert),
  std:isRoot(Cert),
  nssNameConstraintValid(Leaf, Cert),
  notSymantec(Cert),
  ext:larger(ChainLen, -1),
  ext:larger(100, ChainLen).

verified(Leaf, Cert, ChainLen):-
  std:isTimeValid(Cert),
  parent(Cert, P, ChainLen),
  checkKeyUsage(P),
  checkExtendedKeyUsage(Cert),
  maxIntermediatesOkay(ChainLen),
  % Firefox-specific
  validSHA1(Cert),
  notInOneCRL(Cert),
  notRevoked(Cert),
  % BLOCKED: parentNameConstraints(Cert, Parent), % BLOCKED ON PARSING
  % BLOCKED: checkCertificatePolicies(Cert), % BLOCKED ON PARSING
  % checkRequiredTLSFeaturesMatch(Cert, Parent), % Seems like this is done to match cert with issuer... which we do automatically?
  % checkDigestSignedByIssuer(Cert, Parent), % Checked by webpki AFAIK
  % checkSubjectPublicKeyInfo(cert), % This checks for issues in the certificate that may cause buffer overflows in trust domain... skip for now.
  ext:add(ChainLenNew, ChainLen, 1),
  verified(Leaf, P, ChainLenNew).

% Error reporting clause
firefoxNameMatches(Cert) :-
  checks:domainMatchCheckEnabled(false),
  std:isCert(Cert).

firefoxNameMatches(Cert) :-
  certs:extensionExists(Cert, "SubjectAlternativeNames", true),
  std:nameMatchesSAN(Cert).

% Check CN ONLY if SAN not present
firefoxNameMatches(Cert) :-
  certs:extensionExists(Cert, "SubjectAlternativeNames", false),
  std:nameMatchesCN(Cert).

% in seconds
duration27MonthsPlusSlop(71712000).

isNSSTimeValid(Cert):-
  \+ev:isEV(Cert).

isNSSTimeValid(Cert):-
  ev:isEV(Cert),
  duration27MonthsPlusSlop(ValidDuration),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  ext:subtract(Duration, Upper, Lower),
  ext:geq(ValidDuration, Duration).

verified(Cert):-
  \+std:isCA(Cert),
  checkKeyUsage(Cert),
  checkExtendedKeyUsage(Cert),
  firefoxNameMatches(Cert),
  isNSSTimeValid(Cert),
  verified(Cert, Cert, -1).
