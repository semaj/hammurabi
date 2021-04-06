:- use_module(firefox).
:- use_module(chrome).

chrome_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):-
    Fingerprint = "aa",
    chrome:verified_ch(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    \+firefox:verified_fx(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).

firefox_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):-
    Fingerprint = "aa",
    SANList = ["www.bing.com", ""],
    % BasicConstraints = none,
    % KeyUsage = ExtKeyUsage, ExtKeyUsage = RootKeyUsage, RootKeyUsage = [],
    % CertPolicies = [["1.3.6.1.4.1.6334.1.100.1", _37470]|_37448],
    % RootSubject = ["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"],
    % RootFingerprint = "806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A",
    % RootBasicConstraints = [1, _37656],
    firefox:verified_fx(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    \+chrome:verified_ch(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).