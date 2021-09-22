
ev:isEV(Cert).
checks:domainMatchCheckEnabled(false).
checks:revokedCheckEnabled(false).
checks:nssNameConstraintCheckEnabled(false).
checks:chainLengthCheckEnabled(false).
checks:parentNotCACheckEnabled(false).
checks:timeValidCheckEnabled(false).

ext:geq(ChainLen, ChainLen).
ext:s_startswith("*.", Pattern).
ext:s_substring(0, 1, P, Pattern).
ext:s_endswith(CommonName, P).
ext:s_occurrences(".", N, Pattern).
ext:s_occurrences(".", CommonName, N).
ext:s_containstldwildcard(Name).
ext:equal(Pattern, CommonName).
ext:unequal(Cert, Y).
ext:add(ChainLen, Effective, SelfCount).
ext:larger(T, Lower).

certs:signatureAlgorithm(Cert, Algorithm).
certs:pathLimit(Cert, Limit).
certs:san(Cert, Name).
certs:serialNumber(Cert, Serial).
certs:commonName(Cert, Subject).
certs:notBefore(Cert, Lower).
certs:notAfter(Cert, Upper).
certs:keyUsageExt(Cert, true).
certs:keyUsage(Cert, Usage).
certs:fingerprint(Cert, Fingerprint).
certs:basicConstraintsExt(Cert, true).
certs:isCA(Cert, true).
certs:issuer(Cert, Y).
certs:stapledOcspValid(Cert, false).
certs:stapledOcspExpired(Cert, true).
certs:stapledOcspVerified(Cert, false).
certs:ocspExpired(Cert, R, true).
certs:ocspValid(Cert, R, false).
certs:ocspVerified(Cert, R, false).
certs:ocspStatus(Cert, Responder, revoked).
certs:ocspResponder(Cert, R).
certs:extendedKeyUsage(Cert, serverAuth).
certs:extendedKeyUsageExt(Cert, false).
certs:sanExt(Cert, true).

env:ipToNumber(0, 1, 1, 168, 192, H).
env:domain("jameslarisch.com").
env:tlsVersion(2).
env:max_intermediates(5).
env:hostIp(H):-
    env:ipToNumber(192,168,1,1,0,H).

% This is our own Ruby CA for frankencert testing.
env:trusted_roots("806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A").

env:trusted_roots("02ED0EB28C14DA45165C566791700D6451D7FB56F0B2AB1D3B8EB070E56EDFF5").

% Sugar
% is a Cert if it has serial number
std:isCert(Cert):-
    certs:serialNumber(Cert, Serial).

% common name match function
% wildcard clause
std:stringMatch(Pattern, CommonName):-
    ext:s_startswith(Pattern, "*."),
    ext:s_substring(Pattern, 1, 0, P),
    ext:s_endswith(CommonName, P),
    ext:s_occurrences(Pattern, ".", N),
    ext:s_occurrences(CommonName, ".", N).

% common name match function
% exact clause
std:stringMatch(Pattern, CommonName):-
    ext:equal(Pattern, CommonName).


% domain name matches one of the names in SAN
std:nameMatchesSAN(Cert) :-
    env:domain(D),
    certs:san(Cert, Name),
    \+ext:s_containstldwildcard(Name),
    std:stringMatch(Name, D).

% domain name matches common name
std:nameMatchesCN(Cert):-
    env:domain(D),
    certs:commonName(Cert, Subject),
    \+ext:s_containstldwildcard(Subject),
    std:stringMatch(Subject, D).

% domain name matches any
std:nameMatches(Cert):-
  std:nameMatchesSAN(Cert).

std:nameMatches(Cert):-
  std:nameMatchesCN(Cert).

% Error reporting clause
std:isTimeValid(Cert):-
    checks:timeValidCheckEnabled(false),
    std:isCert(Cert).

% time validity check. between Lower and Upper
std:isTimeValid(Cert):-
    ext:equal(T, 1618246820),
    % ext:now(T),
    certs:notBefore(Cert, Lower),
    certs:notAfter(Cert, Upper),
    ext:larger(T, Lower),
    ext:larger(Upper, T).

% check if key usage allowed
% keyUsage extension exists clause
std:usageAllowed(Cert, Usage):-
    certs:keyUsageExt(Cert, true),
    certs:keyUsage(Cert, Usage).

% check if Cert is a trusted root
std:isRoot(Cert):-
    certs:fingerprint(Cert, Fingerprint),
    env:trusted_roots(Fingerprint).

% Error reporting clause
std:isCA(Cert):-
    checks:parentNotCACheckEnabled(false),
    std:isCert(Cert).

% Basic Constraints checks
% CA bit set
std:isCA(Cert):-
    certs:basicConstraintsExt(Cert, true),
    certs:isCA(Cert, true).

% Error reporting clause
std:pathLengthOkay(Cert, ChainLen, SelfCount):-
    checks:chainLengthCheckEnabled(false),
    std:isCert(Cert),
    ext:geq(ChainLen, ChainLen),
    ext:geq(SelfCount, SelfCount).

% Path length is okay if the extension doesn't exist
std:pathLengthOkay(Cert, ChainLen, SelfCount) :-
  certs:basicConstraintsExt(Cert, false),
  ext:geq(ChainLen, ChainLen),
  ext:geq(SelfCount, Selfcount).

% Basic Constraints checks
% Path length constraint
std:pathLengthOkay(Cert, ChainLen, SelfCount):-
    certs:basicConstraintsExt(Cert, true),
    certs:pathLimit(Cert, Limit),
    ext:add(ChainLen, Effective, SelfCount),
    ext:larger(Limit, Effective).

std:pathLengthOkay(Cert, ChainLen, SelfCount):-
    certs:basicConstraintsExt(Cert, true),
    certs:pathLimit(Cert, none),
    ext:geq(ChainLen, ChainLen),
    ext:geq(SelfCount, SelfCount).

std:maxIntermediatesOkay(ChainLen):-
    checks:chainLengthCheckEnabled(false),
    ext:larger(ChainLen, -1),
    ext:larger(1000, ChainLen).

% Custom limit on intermediate certs check
% exempts trusted certs from limit
std:maxIntermediatesOkay(ChainLen):-
    env:max_intermediates(M),
    ext:larger(M, ChainLen).

% descendant. also works for ancestor
% direct parent clause
std:descendant(Cert, Y):-
    certs:issuer(Cert, Y),
    ext:unequal(Cert, Y).

% descendant. also works for ancestor
% chain clause
std:descendant(Cert, Y):-
    certs:issuer(Cert, Y),
    ext:unequal(Cert, Z),
    std:descendant(Z, Y).



onecrl:onecrl("D2D1DA9C14F62D97465F337D26788C079EE5450A42D3DADB00AD0EB20F18EC49").



firefox:symantecFingerprint("FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A").
irefox:symantecFingerprint("69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79").
firefox:symantecFingerprint("9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF").
firefox:symantecFingerprint("2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C").

firefox:tubitak1Fingerprint("46EDC3689046D53A453FB3104AB80DCAEC658B2660EA1629DD7E867990648716").
firefox:tubitak1Subtree("*.gov.tr").
firefox:tubitak1Subtree("*.k12.tr").
firefox:tubitak1Subtree("*.pol.tr").
firefox:tubitak1Subtree("*.mil.tr").
firefox:tubitak1Subtree("*.tsk.tr").
firefox:tubitak1Subtree("*.kep.tr").
firefox:tubitak1Subtree("*.bel.tr").
firefox:tubitak1Subtree("*.edu.tr").
firefox:tubitak1Subtree("*.org.tr").

firefox:anssiFingerprint("B9BEA7860A962EA3611DAB97AB6DA3E21C1068B97D55575ED0E11279C11C8932").
firefox:anssiSubtree("*.fr").
firefox:anssiSubtree("*.gp").
firefox:anssiSubtree("*.gf").
firefox:anssiSubtree("*.mq").
firefox:anssiSubtree("*.re").
firefox:anssiSubtree("*.yt").
firefox:anssiSubtree("*.pm").
firefox:anssiSubtree("*.bl").
firefox:anssiSubtree("*.mf").
firefox:anssiSubtree("*.wf").
firefox:anssiSubtree("*.pf").
firefox:anssiSubtree("*.nc").
firefox:anssiSubtree("*.tf").

% Error reporting clause
firefox:nssNameConstraintValid(Leaf, Root) :-
  checks:nssNameConstraintCheckEnabled(false),
  std:isCert(Leaf),
  std:isCert(Root).

% See: https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
firefox:nssNameConstraintValid(Leaf, Root) :-
  certs:fingerprint(Root, F),
  \+firefox:anssiFingerprint(F),
  \+firefox:tubitak1Fingerprint(F),
  std:isCert(Leaf).

firefox:nssNameConstraintValid(Leaf, Root) :-
  firefox:tubitak1Fingerprint(F),
  certs:fingerprint(Root, F),
  certs:san(Leaf, Name),
  firefox:tubitak1Subtree(Tree),
  std:stringMatch(Tree, Name).

firefox:nssNameConstraintValid(Leaf, Root) :-
  firefox:anssiFingerprint(F),
  certs:fingerprint(Root, F),
  certs:san(Leaf, Name),
  firefox:anssiSubtree(Tree),
  std:stringMatch(Tree, Name).

% Error reporting clause
firefox:notRevoked(Cert) :-
  checks:revokedCheckEnabled(false),
  std:isCert(Cert).

firefox:notRevoked(Cert) :-
  firefox:shortLived(Cert). % Firefox uses 10 days

firefox:notRevoked(Cert) :-
  std:isCert(Cert),
  \+firefox:ocspRevoked(Cert).

firefox:stapledResponseError(Cert) :-
  certs:stapledOcspValid(Cert, false).

firefox:stapledResponseError(Cert) :-
  certs:stapledOcspExpired(Cert, true).

firefox:stapledResponseError(Cert) :-
  certs:stapledOcspVerified(Cert, false).

firefox:ocspResponseError(Cert) :-
  certs:ocspExpired(Cert, R, true).

firefox:ocspResponseError(Cert) :-
  certs:ocspValid(Cert, R, false).

firefox:ocspResponseError(Cert) :-
  certs:ocspVerified(Cert, R, false).

firefox:ocspRevoked(Cert) :-
  certs:ocspStatus(Cert, Responder, revoked).

firefox:ocspRevoked(Cert) :-
  certs:ocspStatus(Cert, Responder, unknown).

firefox:ocspRevoked(Cert) :-
  firefox:stapledResponseError(Cert),
  \+certs:ocspResponder(Cert, R).

firefox:ocspRevoked(Cert) :-
  ev:isEV(Cert),
  \+certs:ocspResponder(Cert, R).

firefox:ocspRevoked(Cert) :-
  firefox:ocspResponseError(Cert),
  firefox:stapledResponseError(Cert).

firefox:ocspRevoked(Cert) :-
  ev:isEV(Cert),
  firefox:ocspResponseError(Cert).

firefox:tenDaysInSeconds(864001).

firefox:shortLived(Cert) :-
  firefox:tenDaysInSeconds(ValidDuration),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  ext:subtract(Duration, Upper, Lower),
  ext:larger(ValidDuration, Duration).

firefox:notInOneCRL(Cert) :-
  certs:fingerprint(Cert, Fingerprint),
  \+onecrl:onecrl(Fingerprint).

firefox:checkKeyUsage(Cert) :-
  std:isCA(Cert),
  certs:keyUsageExt(Cert, true),
  std:usageAllowed(Cert, keyCertSign).

firefox:checkKeyUsage(Cert) :-
  certs:keyUsageExt(Cert, false).

firefox:checkKeyUsage(Cert) :-
  \+std:isCA(Cert),
  std:usageAllowed(Cert, digitalSignature).

firefox:checkKeyUsage(Cert) :-
  \+std:isCA(Cert),
  std:usageAllowed(Cert, keyEncipherment).

firefox:checkKeyUsage(Cert) :-
  \+std:isCA(Cert),
  std:usageAllowed(Cert, keyAgreement).


firefox:notSymantec(Cert) :-
  certs:fingerprint(Cert, F),
  \+firefox:symantecFingerprint(F).

firefox:checkKeyCertSign(Cert) :-
  std:usageAllowed(Cert, keyCertSign).

firefox:checkKeyCertSign(Cert) :-
  certs:keyUsageExt(Cert, false).

firefox:parent(C, P, ChainLen):-
    certs:issuer(C, P),
    std:isCA(P),
    firefox:checkKeyCertSign(P),
    std:pathLengthOkay(P, ChainLen, 0).

firefox:validSHA1(Cert) :-
  certs:signatureAlgorithm(Cert, Algorithm),
  % ecdsa with sha1
  ext:unequal(Algorithm, "1.2.840.10045.4.1"),
  % rsa signature with sha1
  ext:unequal(Algorithm, "1.3.14.3.2.29"),
  % rsa encryption with sha1
  ext:unequal(Algorithm, "1.2.840.113549.1.1.5").

firefox:checkExtendedKeyUsage(Cert) :-
  std:isCA(Cert),
  certs:extendedKeyUsage(Cert, serverAuth).

firefox:checkExtendedKeyUsage(Cert):-
  \+std:isCA(Cert),
  \+certs:extendedKeyUsage(Cert, oCSPSigning),
  certs:extendedKeyUsage(Cert, serverAuth).

firefox:checkExtendedKeyUsage(Cert) :-
  certs:extendedKeyUsageExt(Cert, false).

% Override kb_env.pl
firefox:max_intermediates(5).

% Error reporting clause
firefox:maxIntermediatesOkay(ChainLen):-
  checks:chainLengthCheckEnabled(false),
  ext:larger(ChainLen, -1),
  ext:larger(100, ChainLen).

% Custom limit on intermediate certs check
% exempts trusted certs from limit
firefox:maxIntermediatesOkay(ChainLen):-
  firefox:max_intermediates(M),
  ext:larger(M, ChainLen).

firefox:verified(Leaf, Cert, ChainLen):-
  std:isTimeValid(Cert),
  std:isRoot(Cert),
  firefox:nssNameConstraintValid(Leaf, Cert),
  firefox:notSymantec(Cert),
  ext:larger(ChainLen, -1),
  ext:larger(100, ChainLen).

firefox:verified(Leaf, Cert, ChainLen):-
  std:isTimeValid(Cert),
  firefox:parent(Cert, P, ChainLen),
  firefox:checkKeyUsage(P),
  firefox:checkExtendedKeyUsage(Cert),
  firefox:maxIntermediatesOkay(ChainLen),
  % Firefox-specific
  firefox:validSHA1(Cert),
  firefox:notInOneCRL(Cert),
  firefox:notRevoked(Cert),
  % BLOCKED: firefox:parentNameConstraints(Cert, Parent), % BLOCKED ON PARSING
  % BLOCKED: firefox:checkCertificatePolicies(Cert), % BLOCKED ON PARSING
  % firefox:checkRequiredTLSFeaturesMatch(Cert, Parent), % Seems like this is done to match cert with issuer... which we do automatically?
  % firefox:checkDigestSignedByIssuer(Cert, Parent), % Checked by webpki AFAIK
  % firefox:checkSubjectPublicKeyInfo(cert), % This checks for issues in the certificate that may cause buffer overflows in trust domain... skip for now.
  ext:add(ChainLenNew, ChainLen, 1),
  firefox:verified(Leaf, P, ChainLenNew).

% Error reporting clause
firefox:firefoxNameMatches(Cert) :-
  checks:domainMatchCheckEnabled(false),
  std:isCert(Cert).

firefox:firefoxNameMatches(Cert) :-
  certs:sanExt(Cert, true),
  std:nameMatchesSAN(Cert).

% Check CN ONLY if SAN not present
firefox:firefoxNameMatches(Cert) :-
  certs:sanExt(Cert, false),
  std:nameMatchesCN(Cert).

% in seconds
firefox:duration27MonthsPlusSlop(71712000).

firefox:isNSSTimeValid(Cert):-
  \+ev:isEV(Cert).

firefox:isNSSTimeValid(Cert):-
  ev:isEV(Cert),
  firefox:duration27MonthsPlusSlop(ValidDuration),
  certs:notBefore(Cert, Lower),
  certs:notAfter(Cert, Upper),
  ext:subtract(Duration, Upper, Lower),
  ext:geq(ValidDuration, Duration).

firefox:verified(Cert):-
  \+std:isCA(Cert),
  firefox:checkKeyUsage(Cert),
  firefox:checkExtendedKeyUsage(Cert),
  firefox:firefoxNameMatches(Cert),
  firefox:isNSSTimeValid(Cert),
  firefox:verified(Cert, Cert, -1).
