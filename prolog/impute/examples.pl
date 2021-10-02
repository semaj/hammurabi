:- use_module(firefox).
:- use_module(chrome).
:- use_module(library(clpfd)).
:- set_prolog_flag(toplevel_print_anon, false).
:- set_prolog_flag(answer_write_options,[max_depth(0)]).
:- style_check(-singleton).

firefox_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):-
    types:sANList(SANList),
    types:timestamp(Lower),
    types:timestamp(Upper),
    types:algorithm(Algorithm),
    types:basicConstraints(BasicConstraints),
    types:keyUsageList(KeyUsage),
    types:extKeyUsageList(ExtKeyUsage),
    types:certificatePolicy(CertPolicies),
    types:stapledResponse(StapledResponse),
    types:ocspResponse(OcspResponse),
    types:timestamp(RootLower),
    types:timestamp(RootUpper),
    types:basicConstraints(RootBasicConstraints),
    types:keyUsageList(RootKeyUsage),
    verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    \+verified_chrome(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).

chrome_only(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage):-
    types:sANList(SANList),
    types:timestamp(Lower),
    types:timestamp(Upper),
    types:algorithm(Algorithm),
    types:basicConstraints(BasicConstraints),
    types:keyUsageList(KeyUsage),
    types:extKeyUsageList(ExtKeyUsage),
    types:certificatePolicy(CertPolicies),
    types:stapledResponse(StapledResponse),
    types:ocspResponse(OcspResponse),
    types:timestamp(RootLower),
    types:timestamp(RootUpper),
    types:basicConstraints(RootBasicConstraints),
    types:keyUsageList(RootKeyUsage),
    verified_chrome(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    \+verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).

both():-
    Fingerprint = "",
    SANList = ["www.bing.com"],
    Subject = "",
    Lower = 1617423689,
    Upper = 1618387690,
    Algorithm = "1.2.840.10040.4.3",
    BasicConstraints = [],
    KeyUsage = [],
    ExtKeyUsage = [oCSPSigning],
    CertPolicies = ["1.3.6.1.4.1.6334.1.100.1", 0],
    StapledResponse = [verified, not_expired, valid],
    OcspResponse = [verified, not_expired, valid, good],
    RootSubject = ["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"],
    RootFingerprint = "5A2FC03F0C83B090BBFA40604B0988446C7636183DF9846E17101A447FB8EFD6",
    RootLower = 631170000,
    RootUpper = 1618287689,
    RootBasicConstraints = [true, 10],
    RootKeyUsage = [],
    verified_chrome(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage),
    verified_firefox(Fingerprint, SANList, Subject, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, CertPolicies, StapledResponse, OcspResponse, RootSubject, RootFingerprint, RootLower, RootUpper, RootBasicConstraints, RootKeyUsage).
