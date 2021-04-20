:- use_module(firefox).
:- use_module(chrome).
:- use_module(library(clpfd)).
:- set_prolog_flag(toplevel_print_anon, false).
:- set_prolog_flag(answer_write_options,[max_depth(0)]).
:- style_check(-singleton).

disagree(Lower, Upper):-
    Fingerprint = "aa",
    SANList = ["www.bing.com"],
    Subject = "",
    % Lower = 1546575689,
    % Upper = 1618287689,
    Algorithm = "1.2.840.10040.4.3",
    BasicConstraints = [0, 1],
    KeyUsage = [digitalSignature],
    ExtKeyUsage = [],
    CertPolicies = [["1.3.6.1.4.1.6334.1.100.1", 0]],
    StapledResponse = [verified, not_expired, valid],
    OcspResponse = [],
    RootSubject = ["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"],
    RootFingerprint = "806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A",
    RootLower = 1617688610,
    RootUpper = 1622222222,
    RootBasicConstraints = [1, 10],
    RootKeyUsage = [],
    verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    #\verified_chrome(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).


disagree(KeyUsage):-
    Fingerprint = "aa",
    SANList = ["www.bing.com"],
    Subject = "",
    Lower = 1546575689,
    Upper = 1618287689,
    Algorithm = "1.2.840.10040.4.3",
    BasicConstraints = [0, 1],
    KeyUsage = [],
    ExtKeyUsage = [],
    CertPolicies = [["1.3.6.1.4.1.6334.1.100.1", 0]],
    StapledResponse = [verified, not_expired, valid],
    OcspResponse = [],
    RootSubject = ["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"],
    RootFingerprint = "806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A",
    RootLower = 1617688610,
    RootUpper = 1622222222,
    RootBasicConstraints = [1, 10],
    RootKeyUsage = [],
    verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    verified_chrome(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).

both():-
    Fingerprint = "aa",
    SANList = ["www.bing.com"],
    Subject = "",
    Lower = 1617423689,
    Upper = 1618287689,
    Algorithm = "1.2.840.10040.4.3",
    BasicConstraints = [],
    KeyUsage = [],
    ExtKeyUsage = [serverAuth],
    CertPolicies = [["1.3.6.1.4.1.6334.1.100.1", 0]],
    StapledResponse = [verified, not_expired, valid],
    OcspResponse = [],
    RootSubject = ["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"],
    RootFingerprint = "806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A",
    RootLower = 631170000,
    RootUpper = 1618287689,
    RootBasicConstraints = [1, 10],
    RootKeyUsage = [],
    verified_chrome(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).
