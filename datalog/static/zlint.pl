:- use_module(std). 
:- use_module(env).
:- use_module(certs).
:- use_module(cert_0).
:- use_module(cert_1).
:- use_module(ext).
:- use_module(browser).
:- use_module(checks).

% The following functions are taken from zlint
% specifically the cabf_br tests  
% but reimplemented using Datalog 
% See www.github.com/zmap/zlint for more information 

% Checks whether or not the common 
% name is missing
caCommonNameMissing(Cert) :- 
    certs:commonName(Cert, Name),
    ext:equal(Name, ""). 

% Checks whether the country name 
% is invalid
caCountryNameInvalid(Cert) :- 
  certs:country(Cert, Country), 
  \+val_country(Country).

% Checks whether or not country name 
% is missing 
caCountryNameMissing(Cert) :- 
    certs:country(Cert, Country),
    ext:equal(Country, ""). 

% countryName must not appear if 
% the organizationName, givenName, 
% and surname are absent
countryNameMustNotAppearApplies(Cert) :- 
  givenNameMissing(Cert), 
  surnameMissing(Cert),
  caCountryNameMissing(Cert).

countryNameMustNotAppear(Cert) :- 
  caCountryNameMissing(Cert).

% Country Name must appear if 
% organizationName, givenName 
% Or surname is present 
countryNameMustAppearApplies(Cert) :- 
  \+organizationNameMissing(Cert).

countryNameMustAppearApplies(Cert) :- 
  \+givenNameMissing(Cert).

countryNameMustAppearApplies(Cert) :- 
  \+surnameMissing(Cert).

countryNameMustAppear(Cert) :- 
  \+caCountryNameMissing(Cert).

% If certificate asserts policy identifier 
% 2.23.140.1.2.3 then it must include either 
% (1) either organizationName, givenName, or surname
% (2) localityName
% (3) stateOrProvinceName
% (4) countryName

certPolicyIvRequiresOrgGivenOrSurname(Cert) :- 
  \+organizationNameMissing(Cert). 

certPolicyIvRequiresOrgGivenOrSurname(Cert) :- 
  \+givenNameMissing(Cert). 

certPolicyIvRequiresOrgGivenOrSurname(Cert) :- 
  \+surnameMissing(Cert).

certPolicyIvRequireslocalityName(Cert) :- 
  \+localityNameMissing(Cert).

certPolicyIvRequiresStateOrProvinceName(Cert) :- 
  \+stateOrProvinceNameMissing(Cert).

% Seems off but taken from zlint github
certPolicyIvRequiresLocalityOrProvinceName(Cert) :- 
  \+localityNameMissing(Cert).

certPolicyIvRequiresLocalityOrProvinceName(Cert) :- 
  \+stateOrProvinceNameMissing(Cert).

certPolicyIvRequiresCountry(Cert) :- 
  \+caCountryNameMissing(Cert). 

% If certificate asserts policy identifier 
% 2.23.140.1.2.2 then it MUST include
% organizationName, localityName,
% stateOrProvinceName, and countryName

certPolicyRequiresOrg(Cert) :- 
  \+organizationNameMissing(Cert). 

certPolicyOvRequires(Cert) :- 
  \+organizationNameMissing(Cert), 
  \+localityNameMissing(Cert), 
  \+stateOrProvinceNameMissing(Cert), 
  \+caCountryNameMissing(Cert).

% SAN must appear 
extSanMissing(Cert) :- 
  certs:san(Cert, Name), 
  ext:equal(Name, ""). 

extSanMissing(Cert) :- 
  certs:sanExt(Cert, Value), 
  ext:equal(Value, false).

% Basic Constraints checks
% CA bit set
caIsCa(Cert) :-
    certs:isCA(Cert, true).

% All of the helper methods will be posted below 
organizationNameMissing(Cert) :- 
  certs:organizationName(Cert, Name),
  ext:equal(Name, "").

givenNameMissing(Cert) :- 
  certs:givenName(Cert, Name),
  ext:equal(Name, "").

surnameMissing(Cert) :- 
  certs:surname(Cert, Name),
  ext:equal(Name, "").

stateOrProvinceNameMissing(Cert) :- 
  certs:stateOrProvinceName(Cert, Name), 
  ext:equal(Name, ""). 

localityNameMissing(Cert) :- 
  certs:localityName(Cert, Name),
  ext:equal(Name, "").


% Below is the list of valid countries from a CA 
val_country("AD").
val_country("AE").
val_country("AF").
val_country("AG").
val_country("AI").
val_country("AL").
val_country("AM").
val_country("AN").
val_country("AO").
val_country("AQ").
val_country("AR").
val_country("AS").
val_country("AT").
val_country("AU").
val_country("AW").
val_country("AX").
val_country("AZ").
val_country("BA").
val_country("BB").
val_country("BD").
val_country("BE").
val_country("BF").
val_country("BG").
val_country("BH").
val_country("BI").
val_country("BJ").
val_country("BL").
val_country("BM").
val_country("BN").
val_country("BO").
val_country("BQ").
val_country("BR").
val_country("BS").
val_country("BT").
val_country("BV").
val_country("BW").
val_country("BY").
val_country("BZ").
val_country("CA").
val_country("CC").
val_country("CD").
val_country("CF").
val_country("CG").
val_country("CH").
val_country("CI").
val_country("CK").
val_country("CL").
val_country("CM").
val_country("CN").
val_country("CO").
val_country("CR").
val_country("CU").
val_country("CV").
val_country("CW").
val_country("CX").
val_country("CY").
val_country("CZ").
val_country("DE").
val_country("DJ").
val_country("DK").
val_country("DM").
val_country("DO").
val_country("DZ").
val_country("EC").
val_country("EE").
val_country("EG").
val_country("EH").
val_country("ER").
val_country("ES").
val_country("ET").
val_country("FI").
val_country("FJ").
val_country("FK").
val_country("FM").
val_country("FO").
val_country("FR").
val_country("GA").
val_country("GB").
val_country("GD").
val_country("GE").
val_country("GF").
val_country("GG").
val_country("GH").
val_country("GI").
val_country("GL").
val_country("GM").
val_country("GN").
val_country("GP").
val_country("GQ").
val_country("GR").
val_country("GS").
val_country("GT").
val_country("GU").
val_country("GW").
val_country("GY").
val_country("HK").
val_country("HM").
val_country("HN").
val_country("HR").
val_country("HT").
val_country("HU").
val_country("ID").
val_country("IE").
val_country("IL").
val_country("IM").
val_country("IN").
val_country("IO").
val_country("IQ").
val_country("IR").
val_country("IS").
val_country("IT").
val_country("JE").
val_country("JM").
val_country("JO").
val_country("JP").
val_country("KE").
val_country("KG").
val_country("KH").
val_country("KI").
val_country("KM").
val_country("KN").
val_country("KP").
val_country("KR").
val_country("KW").
val_country("KY").
val_country("KZ").
val_country("LA").
val_country("LB").
val_country("LC").
val_country("LI").
val_country("LK").
val_country("LR").
val_country("LS").
val_country("LT").
val_country("LU").
val_country("LV").
val_country("LY").
val_country("MA").
val_country("MC").
val_country("MD").
val_country("ME").
val_country("MF").
val_country("MG").
val_country("MH").
val_country("MK").
val_country("ML").
val_country("MM").
val_country("MN").
val_country("MO").
val_country("MP").
val_country("MQ").
val_country("MR").
val_country("MS").
val_country("MT").
val_country("MU").
val_country("MV").
val_country("MW").
val_country("MX").
val_country("MY").
val_country("MZ").
val_country("NA").
val_country("NC").
val_country("NE").
val_country("NF").
val_country("NG").
val_country("NI").
val_country("NL").
val_country("NO").
val_country("NP").
val_country("NR").
val_country("NU").
val_country("NZ").
val_country("OM").
val_country("PA").
val_country("PE").
val_country("PF").
val_country("PG").
val_country("PH").
val_country("PK").
val_country("PL").
val_country("PM").
val_country("PN").
val_country("PR").
val_country("PS").
val_country("PT").
val_country("PW").
val_country("PY").
val_country("QA").
val_country("RE").
val_country("RO").
val_country("RS").
val_country("RU").
val_country("RW").
val_country("SA").
val_country("SB").
val_country("SC").
val_country("SD").
val_country("SE").
val_country("SG").
val_country("SH").
val_country("SI").
val_country("SJ").
val_country("SK").
val_country("SL").
val_country("SM").
val_country("SN").
val_country("SO").
val_country("SR").
val_country("SS").
val_country("ST").
val_country("SV").
val_country("SX").
val_country("SY").
val_country("SZ").
val_country("TC").
val_country("TD").
val_country("TF").
val_country("TG").
val_country("TH").
val_country("TJ").
val_country("TK").
val_country("TL").
val_country("TM").
val_country("TN").
val_country("TO").
val_country("TR").
val_country("TT").
val_country("TV").
val_country("TW").
val_country("TZ").
val_country("UA").
val_country("UG").
val_country("UM").
val_country("US").
val_country("UY").
val_country("UZ").
val_country("VA").
val_country("VC").
val_country("VE").
val_country("VG").
val_country("VI").
val_country("VN").
val_country("VU").
val_country("WF").
val_country("WS").
val_country("YE").
val_country("YT").
val_country("ZA").
val_country("ZM").
val_country("ZW").
val_country("XX").

% The part below is used for testing 
% Currently verified is being autogened 
% by a script

%verified(Cert) :- 
  %std:isCert(Cert), 
  %caCountryNameMissing(Cert).

