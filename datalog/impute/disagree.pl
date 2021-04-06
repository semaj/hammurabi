:- use_module(firefox).
:- use_module(chrome).
:- set_prolog_flag(toplevel_print_anon, false).
:- style_check(-singleton).


chrome_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):-
    Fingerprint = "aa",
    verified_chrome(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    \+verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).

firefox_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):-
    verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    \+verified_chrome(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).

disagree(Lower, Upper):-
    Fingerprint = "aa",
    % Lower = 1341100800,
    % Upper = 1519862399,
    SANList = ["www.bing.com"],
    BasicConstraints = none,
    KeyUsage = [],
    ExtKeyUsage = [],
    CertPolicies = [["1.3.6.1.4.1.6334.1.100.1", 0]],
    RootSubject = ["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"],
    RootFingerprint = "806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A",
    RootBasicConstraints = [1, 10],
    RootLower = 1617688610,
    RootKeyUsage = [],
    firefox_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, RootSubject, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).
