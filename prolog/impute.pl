:- use_module("job/certs").
:- use_module("static/types").
:- use_module("static/chrome").
:- use_module("static/firefox").

setTypes(SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):-
    types:sanList(SANList),
    types:timestamp(Lower),
    types:timestamp(Upper),
    types:algorithm(Algorithm),
    types:basicConstraints(BasicConstraints),
    types:keyUsageList(KeyUsage),
    types:extKeyUsageList(ExtKeyUsage),
    types:evStatus(EVStatus),
    types:stapledResponse(StapledResponse),
    types:ocspResponse(OcspResponse).

both(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):-
    setTypes(SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse),
    firefox:verifiedLeaf(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse),
    chrome:verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage).

firefoxOnly(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):-
    setTypes(SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse),
    firefox:verifiedLeaf(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse),
    \+chrome:verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage).

chromeOnly(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse):-
    setTypes(SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse),
    chrome:verifiedLeaf(Fingerprint, SANList, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage),
    \+firefox:verifiedLeaf(Fingerprint, SANList, CommonName, Lower, Upper, Algorithm, BasicConstraints, KeyUsage, ExtKeyUsage, EVStatus, StapledResponse, OcspResponse).