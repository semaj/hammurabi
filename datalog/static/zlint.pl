:- use_module(std). 
:- use_module(env).
:- use_module(certs).
:- use_module(cert_0).
:- use_module(cert_1).
:- use_module(browser).
:- use_module(checks).
@:- include(certs).
% The following functions are taken from zlint
% specifically the cabf_br tests  
% but reimplemented using Datalog 
% See www.github.com/zmap/zlint for more information 

isCert(Cert) :-
  \+certs:serialNumber(Cert, "").

% Checks whether or not the common 
% name is missing
caCommonNameMissing(Cert) :- 
    certs:commonName(Cert, "").

% Checks whether the country name 
% is invalid
caCountryNameValidApplies(Cert) :-
  isCa(Cert), 
  caCountryNamePresent(Cert). 

caCountryNameValid(Cert) :- 
  certs:country(Cert, Country), 
  val_country(Country).

% Checks whether or not country name 
% is missing 
caCountryNameMissing(Cert) :- 
    certs:country(Cert, "").

caCountryNamePresent(Cert) :- 
  \+caCountryNameMissing(Cert).

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
%countryNameMustAppearApplies(Cert) :- 
%  \+organizationNameMissing(Cert).

%countryNameMustAppearApplies(Cert) :- 
%  \+givenNameMissing(Cert).

%countryNameMustAppearApplies(Cert) :- 
%  \+surnameMissing(Cert).

countryNameMustAppear(Cert) :- 
  \+caCountryNameMissing(Cert).

countryNameMustAppear(Cert) :- 
  organizationNameMissing(Cert), 
  givenNameMissing(Cert), 
  surnameMissing(Cert).

% If certificate asserts policy identifier 
% 2.23.140.1.2.3 then it must include either 
% (1) either organizationName, givenName, or surname
% (2) localityName
% (3) stateOrProvinceName
% (4) countryName

certPolicyIvApplies(Cert) :- 
  certs:certificatePolicies(Cert,  "2.23.140.1.2.3").

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

certPolicyOvApplies(Cert) :- 
  certs:certificatePolicies(Cert, "2.23.140.1.2.2").

certPolicyRequiresOrg(Cert) :- 
  \+organizationNameMissing(Cert). 

certPolicyOvRequires(Cert) :- 
  \+organizationNameMissing(Cert), 
  \+localityNameMissing(Cert), 
  \+stateOrProvinceNameMissing(Cert), 
  \+caCountryNameMissing(Cert).

% Postal Code must not appear if 
% organizationName, givenName, or 
% surname fields are absent 

postalCodeProhibtedApplies(Cert) :- 
  organizationNameMissing(Cert).

postalCodeProhibtedApplies(Cert) :- 
  givenNameMissing(Cert).

postalCodeProhibtedApplies(Cert) :- 
  surnameMissing(Cert).

postalCodeProhibted(Cert) :- 
  postalCodeMissing(Cert).

% CAs must not issue certificates 
% longer than 39 months under 
% any circumstances 

maxLifetime(102560094).

validTimeTooLong(Cert) :- 
  maxLifetime(MaxDuration),
  certs:notBefore(Cert, NotBeforeTime),
  certs:notAfter(Cert, NotAfterTime),
  subtract(Duration, NotAfterTime, NotBeforeTime),
  geq(Duration, MaxDuration).

validTimeNotTooLong(Cert) :- 
  \+validTimeTooLong(Cert).

% SAN must appear 
extSanMissing(Cert) :- 
  certs:san(Cert, "").

extSanMissing(Cert) :- 
  certs:sanExt(Cert, false).

extSanNotMissing(Cert) :- 
  \+extSanMissing(Cert).

% The following lints relate to 
% verifying the RSA if used
rsaApplies(Cert) :- 
  certs:keyAlgorithm(Cert, "1.2.840.113549.1.1.1").

% RSA: Public Exponent must be odd
rsaPublicExponentOdd(Cert) :- 
  certs:rsaExponent(Cert, Exp), 
  modulus(1, Exp, 2).

rsaPublicExponentNotTooSmall(Cert) :- 
  certs:rsaExponent(Cert, Exp),
  geq(Exp, 3).

rsaPublicExponentInRange(Cert) :- 
  certs:rsaExponent(Cert, Exp),
  geq(Exp, 65537). 

rsaPublicExponentInRange(Cert) :- 
  certs:rsaExponent(Cert, Exp),
  \+geq(Exp, 115792089237316195423570985008687907853269984665640564039457584007913129639938). 

rsaModOdd(Cert) :- 
  certs:rsaModulus(Cert, Mod), 
  modulus(1, Mod, 2).

rsaModFactorsSmallerThan752(Cert) :- 
  certs:rsaModulus(Cert, Modulus),
  prime_num(Mod),
  modulus(0, Modulus, Mod).

rsaModNoFactorsSmallerThan752(Cert) :- 
  \+rsaModFactorsSmallerThan752(Cert).

rsaModMoreThan2048Bits(Cert) :- 
  certs:rsaModLength(Cert, Length), 
  geq(Length, 2048).



% Root CA Certificate: Bit positions for
% keyCertSign and cRLSign must be set


% CAs MUST NOT issue any new Subscriber 
% certificates or Subordinate CA certificates 
% using SHA-1 after 1 January 2016
subCertOrSubCaNotUsingSha1(Cert) :- 
  \+certs:keyAlgorithm(Cert, "1.2.840.113549.1.1.5"),
  \+certs:keyAlgorithm(Cert, "1.3.14.3.2.27"), 
  \+certs:keyAlgorithm(Cert, "1.2.840.10045.4.1").

% The following are lints for the dnsName 
% under subject alternative name 
dnsNameApplies(Cert) :- 
  \+caCommonNameMissing(Cert).

dnsNameHasBadChar(Cert) :- 
  certs:commonName(Cert, DNSName),
  string_concat(_, Y, DNSName),
  string_concat(A, _, Y),
  string_length(A, 1),
  \+acceptable(A).

dnsNameHasBadChar(Cert) :- 
  certs:san(Cert, DNSName),
  string_concat(_, Y, DNSName),
  string_concat(A, _, Y),
  string_length(A, 1),
  \+acceptable(A).

dnsNameAllCharsAcceptable(Cert) :- 
  \+dnsNameHasBadChar(Cert).

dnsNameLeftLabelWildcardCorrect(Cert) :- 
  certs:commonName(Cert, DNSName), 
  split_string(DNSName, ".", "", [Left | _]), 
  substring("*", Left),
  Left = "*". 

dnsNameLeftLabelWildcardCorrect(Cert) :- 
  certs:san(Cert, DNSName), 
  split_string(DNSName, ".", "", [Left | _]), 
  substring("*", Left),
  Left = "*". 

dnsNameNotTooLong(Cert) :- 
  certs:commonName(Cert, Label), 
  string_length(Label, Length), 
  \+geq(Length, 64).

dnsNameNotTooLong(Cert) :- 
  certs:san(Cert, Label), 
  string_length(Label, Length), 
  \+geq(Length, 64).

dnsNameIsNotEmptyLabel(Cert) :- 
  \+certs:commonName(Cert, ""). 

dnsNameIsNotEmptyLabel(Cert) :- 
  certs:san(Cert, ""). 

dnsNameContainsBareIANASuffix(Cert) :- 
  certs:commonName(Cert, Label), 
  tld(Label).

dnsNameContainsBareIANASuffix(Cert) :- 
  certs:san(Cert, Label), 
  tld(Label).

dnsNameHyphenInSLD(Cert) :- 
  certs:commonName(Cert, Label), 
  s_startswith(Label, "-").

dnsNameHyphenInSLD(Cert) :- 
  certs:san(Cert, Label), 
  s_startswith(Label, "-").

dnsNameHyphenInSLD(Cert) :- 
  certs:commonName(Cert, Label), 
  s_endswith(Label, "-").

dnsNameHyphenInSLD(Cert) :- 
  certs:san(Cert, Label), 
  s_endswith(Label, "-").

dnsNameUnderscoreInTRD(Cert) :- 
  certs:commonName(Cert, DNSName), 
  substring("_", DNSName).

dnsNameUnderscoreInTRD(Cert) :- 
  certs:san(Cert, DNSName), 
  substring("_", DNSName).

dnsNameWildCardOnlyInLeftLabel(Cert) :- 
  certs:commonName(Cert, DNSName), 
  split_string(DNSName, ".", "", [_ | Rest]),
  forall(member(Rest, Word), 
  \+substring("*", Word)).

dnsNameWildCardOnlyInLeftLabel(Cert) :- 
  certs:san(Cert, DNSName), 
  split_string(DNSName, ".", "", [_ | Rest]),
  forall(member(Rest, Word), 
  \+substring("*", Word)).

% Basic Constraints checks
% CA bit set
isCa(Cert) :-
  certs:basicConstraintsExt(Cert, true),
  certs:isCA(Cert, true).

isNotCa(Cert) :- 
  \+isCa(Cert).

% All of the helper methods will be posted below 
organizationNameMissing(Cert) :- 
  certs:organizationName(Cert, "").

givenNameMissing(Cert) :- 
  certs:givenName(Cert, "").

surnameMissing(Cert) :- 
  certs:surname(Cert, "").

stateOrProvinceNameMissing(Cert) :- 
  certs:stateOrProvinceName(Cert, ""). 

localityNameMissing(Cert) :- 
  certs:localityName(Cert, "").

postalCodeMissing(Cert) :- 
  certs:postalCode(Cert, "").

equal(X, Y):-
    X == Y.

larger(X, Y):-
    X > Y.

geq(X, Y):-
    X >= Y.

add(X, Y, Z):-
    X is Y + Z.

subtract(X, Y, Z):-
    X is Y - Z.

modulus(X, Y, Z) :- 
  X is Y mod Z.

s_endswith(String, Suffix):-
    string_concat(_, Suffix, String).

s_startswith(String, Prefix):-
    string_concat(Prefix, _, String).
  
substring(X,S) :-
   sub_string(S, _Before, _Length, _After, X).

isIPv4(Addr):-
    split_string(Addr, ".", "", Bytes), length(Bytes, 4),
    forall(member(B, Bytes), (
        number_string(NB, B), 
        NB < 256,
        number_string(NB, SNB), B = SNB /* to avoid leading zeroes */
    )).


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

% Acceptable Characters in DNS Name 
acceptable("A").
acceptable("B").
acceptable("C").
acceptable("D").
acceptable("E").
acceptable("F").
acceptable("G").
acceptable("H").
acceptable("I").
acceptable("J").
acceptable("K").
acceptable("L").
acceptable("M").
acceptable("N").
acceptable("O").
acceptable("P").
acceptable("Q").
acceptable("R").
acceptable("S").
acceptable("T").
acceptable("U").
acceptable("V").
acceptable("W").
acceptable("X").
acceptable("Y").
acceptable("Z").
acceptable("a").
acceptable("b").
acceptable("c").
acceptable("d").
acceptable("e").
acceptable("f").
acceptable("g").
acceptable("h").
acceptable("i").
acceptable("j").
acceptable("k").
acceptable("l").
acceptable("m").
acceptable("n").
acceptable("o").
acceptable("p").
acceptable("q").
acceptable("r").
acceptable("s").
acceptable("t").
acceptable("u").
acceptable("v").
acceptable("w").
acceptable("x").
acceptable("y").
acceptable("z").
acceptable("0").
acceptable("1").
acceptable("2").
acceptable("3").
acceptable("4").
acceptable("5").
acceptable("6").
acceptable("7").
acceptable("8").
acceptable("9").
acceptable("-").
acceptable("_").
acceptable("*").

% The numbers below are prime nums 
prime_num(2).
prime_num(3).
prime_num(5).
prime_num(7).
prime_num(11).
prime_num(13).
prime_num(17).
prime_num(19).
prime_num(23).
prime_num(29).
prime_num(31).
prime_num(37).
prime_num(41).
prime_num(43).
prime_num(47).
prime_num(53).
prime_num(59).
prime_num(61).
prime_num(67).
prime_num(71).
prime_num(73).
prime_num(79).
prime_num(83).
prime_num(89).
prime_num(97).
prime_num(101).
prime_num(103).
prime_num(107).
prime_num(109).
prime_num(113).
prime_num(127).
prime_num(131).
prime_num(137).
prime_num(139).
prime_num(149).
prime_num(151).
prime_num(157).
prime_num(163).
prime_num(167).
prime_num(173).
prime_num(179).
prime_num(181).
prime_num(191).
prime_num(193).
prime_num(197).
prime_num(199).
prime_num(211).
prime_num(223).
prime_num(227).
prime_num(229).
prime_num(233).
prime_num(239).
prime_num(241).
prime_num(251).
prime_num(257).
prime_num(263).
prime_num(269).
prime_num(271).
prime_num(277).
prime_num(281).
prime_num(283).
prime_num(293).
prime_num(307).
prime_num(311).
prime_num(353).
prime_num(359).
prime_num(367).
prime_num(373).
prime_num(379).
prime_num(383).
prime_num(313).
prime_num(317).
prime_num(331).
prime_num(337).
prime_num(347).
prime_num(349).
prime_num(389).
prime_num(397).
prime_num(401).
prime_num(409).
prime_num(419).
prime_num(421).
prime_num(431).
prime_num(433).
prime_num(439).
prime_num(443).
prime_num(449).
prime_num(457).
prime_num(461).
prime_num(463).
prime_num(467).
prime_num(479).
prime_num(487).
prime_num(491).
prime_num(499).
prime_num(503).
prime_num(509).
prime_num(521).
prime_num(523).
prime_num(541).
prime_num(547).
prime_num(557).
prime_num(563).
prime_num(569).
prime_num(571).
prime_num(577).
prime_num(587).
prime_num(593).
prime_num(599).
prime_num(601).
prime_num(607).
prime_num(613).
prime_num(617).
prime_num(619).
prime_num(631).
prime_num(641).
prime_num(643).
prime_num(647).
prime_num(653).
prime_num(659).
prime_num(661).
prime_num(673).
prime_num(677).
prime_num(683).
prime_num(691).
prime_num(701).
prime_num(709).
prime_num(719).
prime_num(727).
prime_num(733).
prime_num(739).
prime_num(743).
prime_num(751).

% All Top Level Domains (TLDs)
tld("aaa").
tld("aarp").
tld("abarth").
tld("abb").
tld("abbott").
tld("abbvie").
tld("abc").
tld("able").
tld("abogado").
tld("abudhabi").
tld("ac").
tld("academy").
tld("accenture").
tld("accountant").
tld("accountants").
tld("aco").
tld("active").
tld("actor").
tld("ad").
tld("adac").
tld("ads").
tld("adult").
tld("ae").
tld("aeg").
tld("aero").
tld("aetna").
tld("af").
tld("afamilycompany").
tld("afl").
tld("africa").
tld("ag").
tld("agakhan").
tld("agency").
tld("ai").
tld("aig").
tld("aigo").
tld("airbus").
tld("airforce").
tld("airtel").
tld("akdn").
tld("al").
tld("alfaromeo").
tld("alibaba").
tld("alipay").
tld("allfinanz").
tld("allstate").
tld("ally").
tld("alsace").
tld("alstom").
tld("am").
tld("amazon").
tld("americanexpress").
tld("americanfamily").
tld("amex").
tld("amfam").
tld("amica").
tld("amsterdam").
tld("analytics").
tld("android").
tld("anquan").
tld("anz").
tld("ao").
tld("aol").
tld("apartments").
tld("app").
tld("apple").
tld("aq").
tld("aquarelle").
tld("ar").
tld("arab").
tld("aramco").
tld("archi").
tld("army").
tld("arpa").
tld("art").
tld("arte").
tld("as").
tld("asda").
tld("asia").
tld("associates").
tld("at").
tld("athleta").
tld("attorney").
tld("au").
tld("auction").
tld("audi").
tld("audible").
tld("audio").
tld("auspost").
tld("author").
tld("auto").
tld("autos").
tld("avianca").
tld("aw").
tld("aws").
tld("ax").
tld("axa").
tld("az").
tld("azure").
tld("ba").
tld("baby").
tld("baidu").
tld("banamex").
tld("bananarepublic").
tld("band").
tld("bank").
tld("bar").
tld("barcelona").
tld("barclaycard").
tld("barclays").
tld("barefoot").
tld("bargains").
tld("baseball").
tld("basketball").
tld("bauhaus").
tld("bayern").
tld("bb").
tld("bbc").
tld("bbt").
tld("bbva").
tld("bcg").
tld("bcn").
tld("bd").
tld("be").
tld("beats").
tld("beauty").
tld("beer").
tld("bentley").
tld("berlin").
tld("best").
tld("bestbuy").
tld("bet").
tld("bf").
tld("bg").
tld("bh").
tld("bharti").
tld("bi").
tld("bible").
tld("bid").
tld("bike").
tld("bing").
tld("bingo").
tld("bio").
tld("biz").
tld("bj").
tld("black").
tld("blackfriday").
tld("blanco").
tld("blockbuster").
tld("blog").
tld("bloomberg").
tld("blue").
tld("bm").
tld("bms").
tld("bmw").
tld("bn").
tld("bnl").
tld("bnpparibas").
tld("bo").
tld("boats").
tld("boehringer").
tld("bofa").
tld("bom").
tld("bond").
tld("boo").
tld("book").
tld("booking").
tld("boots").
tld("bosch").
tld("bostik").
tld("boston").
tld("bot").
tld("boutique").
tld("box").
tld("br").
tld("bradesco").
tld("bridgestone").
tld("broadway").
tld("broker").
tld("brother").
tld("brussels").
tld("bs").
tld("bt").
tld("budapest").
tld("bugatti").
tld("build").
tld("builders").
tld("business").
tld("buy").
tld("buzz").
tld("bv").
tld("bw").
tld("by").
tld("bz").
tld("bzh").
tld("ca").
tld("cab").
tld("cafe").
tld("cal").
tld("call").
tld("calvinklein").
tld("cam").
tld("camera").
tld("camp").
tld("cancerresearch").
tld("canon").
tld("capetown").
tld("capital").
tld("capitalone").
tld("car").
tld("caravan").
tld("cards").
tld("care").
tld("career").
tld("careers").
tld("cars").
tld("cartier").
tld("casa").
tld("case").
tld("caseih").
tld("cash").
tld("casino").
tld("cat").
tld("catering").
tld("catholic").
tld("cba").
tld("cbn").
tld("cbre").
tld("cbs").
tld("cc").
tld("cd").
tld("ceb").
tld("center").
tld("ceo").
tld("cern").
tld("cf").
tld("cfa").
tld("cfd").
tld("cg").
tld("ch").
tld("chanel").
tld("channel").
tld("charity").
tld("chase").
tld("chat").
tld("cheap").
tld("chintai").
tld("chloe").
tld("christmas").
tld("chrome").
tld("chrysler").
tld("church").
tld("ci").
tld("cipriani").
tld("circle").
tld("cisco").
tld("citadel").
tld("citi").
tld("citic").
tld("city").
tld("cityeats").
tld("ck").
tld("cl").
tld("claims").
tld("cleaning").
tld("click").
tld("clinic").
tld("clinique").
tld("clothing").
tld("cloud").
tld("club").
tld("clubmed").
tld("cm").
tld("cn").
tld("co").
tld("coach").
tld("codes").
tld("coffee").
tld("college").
tld("cologne").
tld("com").
tld("comcast").
tld("commbank").
tld("community").
tld("company").
tld("compare").
tld("computer").
tld("comsec").
tld("condos").
tld("construction").
tld("consulting").
tld("contact").
tld("contractors").
tld("cooking").
tld("cookingchannel").
tld("cool").
tld("coop").
tld("corsica").
tld("country").
tld("coupon").
tld("coupons").
tld("courses").
tld("cpa").
tld("cr").
tld("credit").
tld("creditcard").
tld("creditunion").
tld("cricket").
tld("crown").
tld("crs").
tld("cruise").
tld("cruises").
tld("csc").
tld("cu").
tld("cuisinella").
tld("cv").
tld("cw").
tld("cx").
tld("cy").
tld("cymru").
tld("cyou").
tld("cz").
tld("dabur").
tld("dad").
tld("dance").
tld("data").
tld("date").
tld("dating").
tld("datsun").
tld("day").
tld("dclk").
tld("dds").
tld("de").
tld("deal").
tld("dealer").
tld("deals").
tld("degree").
tld("delivery").
tld("dell").
tld("deloitte").
tld("delta").
tld("democrat").
tld("dental").
tld("dentist").
tld("desi").
tld("design").
tld("dev").
tld("dhl").
tld("diamonds").
tld("diet").
tld("digital").
tld("direct").
tld("directory").
tld("discount").
tld("discover").
tld("dish").
tld("diy").
tld("dj").
tld("dk").
tld("dm").
tld("dnp").
tld("do").
tld("docs").
tld("doctor").
tld("dodge").
tld("dog").
tld("doha").
tld("domains").
tld("doosan").
tld("dot").
tld("download").
tld("drive").
tld("dtv").
tld("dubai").
tld("duck").
tld("dunlop").
tld("duns").
tld("dupont").
tld("durban").
tld("dvag").
tld("dvr").
tld("dz").
tld("earth").
tld("eat").
tld("ec").
tld("eco").
tld("edeka").
tld("edu").
tld("education").
tld("ee").
tld("eg").
tld("email").
tld("emerck").
tld("energy").
tld("engineer").
tld("engineering").
tld("enterprises").
tld("epost").
tld("epson").
tld("equipment").
tld("er").
tld("ericsson").
tld("erni").
tld("es").
tld("esq").
tld("estate").
tld("esurance").
tld("et").
tld("etisalat").
tld("eu").
tld("eurovision").
tld("eus").
tld("events").
tld("everbank").
tld("exchange").
tld("expert").
tld("exposed").
tld("express").
tld("extraspace").
tld("fage").
tld("fail").
tld("fairwinds").
tld("faith").
tld("family").
tld("fan").
tld("fans").
tld("farm").
tld("farmers").
tld("fashion").
tld("fast").
tld("fedex").
tld("feedback").
tld("ferrari").
tld("ferrero").
tld("fi").
tld("fiat").
tld("fidelity").
tld("fido").
tld("film").
tld("final").
tld("finance").
tld("financial").
tld("fire").
tld("firestone").
tld("firmdale").
tld("fish").
tld("fishing").
tld("fit").
tld("fitness").
tld("fj").
tld("fk").
tld("flickr").
tld("flights").
tld("flir").
tld("florist").
tld("flowers").
tld("flsmidth").
tld("fly").
tld("fm").
tld("fo").
tld("foo").
tld("food").
tld("foodnetwork").
tld("football").
tld("ford").
tld("forex").
tld("forsale").
tld("forum").
tld("foundation").
tld("fox").
tld("fr").
tld("free").
tld("fresenius").
tld("frl").
tld("frogans").
tld("frontdoor").
tld("frontier").
tld("ftr").
tld("fujitsu").
tld("fujixerox").
tld("fun").
tld("fund").
tld("furniture").
tld("futbol").
tld("fyi").
tld("ga").
tld("gal").
tld("gallery").
tld("gallo").
tld("gallup").
tld("game").
tld("games").
tld("gap").
tld("garden").
tld("gay").
tld("gb").
tld("gbiz").
tld("gd").
tld("gdn").
tld("ge").
tld("gea").
tld("gent").
tld("genting").
tld("george").
tld("gf").
tld("gg").
tld("ggee").
tld("gh").
tld("gi").
tld("gift").
tld("gifts").
tld("gives").
tld("giving").
tld("gl").
tld("glade").
tld("glass").
tld("gle").
tld("global").
tld("globo").
tld("gm").
tld("gmail").
tld("gmbh").
tld("gmo").
tld("gmx").
tld("gn").
tld("godaddy").
tld("gold").
tld("goldpoint").
tld("golf").
tld("goo").
tld("goodhands").
tld("goodyear").
tld("goog").
tld("google").
tld("gop").
tld("got").
tld("gov").
tld("gp").
tld("gq").
tld("gr").
tld("grainger").
tld("graphics").
tld("gratis").
tld("green").
tld("gripe").
tld("grocery").
tld("group").
tld("gs").
tld("gt").
tld("gu").
tld("guardian").
tld("gucci").
tld("guge").
tld("guide").
tld("guitars").
tld("guru").
tld("gw").
tld("gy").
tld("hair").
tld("hamburg").
tld("hangout").
tld("haus").
tld("hbo").
tld("hdfc").
tld("hdfcbank").
tld("health").
tld("healthcare").
tld("help").
tld("helsinki").
tld("here").
tld("hermes").
tld("hgtv").
tld("hiphop").
tld("hisamitsu").
tld("hitachi").
tld("hiv").
tld("hk").
tld("hkt").
tld("hm").
tld("hn").
tld("hockey").
tld("holdings").
tld("holiday").
tld("homedepot").
tld("homegoods").
tld("homes").
tld("homesense").
tld("honda").
tld("honeywell").
tld("horse").
tld("hospital").
tld("host").
tld("hosting").
tld("hot").
tld("hoteles").
tld("hotels").
tld("hotmail").
tld("house").
tld("how").
tld("hr").
tld("hsbc").
tld("ht").
tld("htc").
tld("hu").
tld("hughes").
tld("hyatt").
tld("hyundai").
tld("ibm").
tld("icbc").
tld("ice").
tld("icu").
tld("id").
tld("ie").
tld("ieee").
tld("ifm").
tld("iinet").
tld("ikano").
tld("il").
tld("im").
tld("imamat").
tld("imdb").
tld("immo").
tld("immobilien").
tld("in").
tld("inc").
tld("industries").
tld("infiniti").
tld("info").
tld("ing").
tld("ink").
tld("institute").
tld("insurance").
tld("insure").
tld("int").
tld("intel").
tld("international").
tld("intuit").
tld("investments").
tld("io").
tld("ipiranga").
tld("iq").
tld("ir").
tld("irish").
tld("is").
tld("iselect").
tld("ismaili").
tld("ist").
tld("istanbul").
tld("it").
tld("itau").
tld("itv").
tld("iveco").
tld("iwc").
tld("jaguar").
tld("java").
tld("jcb").
tld("jcp").
tld("je").
tld("jeep").
tld("jetzt").
tld("jewelry").
tld("jio").
tld("jlc").
tld("jll").
tld("jm").
tld("jmp").
tld("jnj").
tld("jo").
tld("jobs").
tld("joburg").
tld("jot").
tld("joy").
tld("jp").
tld("jpmorgan").
tld("jprs").
tld("juegos").
tld("juniper").
tld("kaufen").
tld("kddi").
tld("ke").
tld("kerryhotels").
tld("kerrylogistics").
tld("kerryproperties").
tld("kfh").
tld("kg").
tld("kh").
tld("ki").
tld("kia").
tld("kim").
tld("kinder").
tld("kindle").
tld("kitchen").
tld("kiwi").
tld("km").
tld("kn").
tld("koeln").
tld("komatsu").
tld("kosher").
tld("kp").
tld("kpmg").
tld("kpn").
tld("kr").
tld("krd").
tld("kred").
tld("kuokgroup").
tld("kw").
tld("ky").
tld("kyoto").
tld("kz").
tld("la").
tld("lacaixa").
tld("ladbrokes").
tld("lamborghini").
tld("lamer").
tld("lancaster").
tld("lancia").
tld("lancome").
tld("land").
tld("landrover").
tld("lanxess").
tld("lasalle").
tld("lat").
tld("latino").
tld("latrobe").
tld("law").
tld("lawyer").
tld("lb").
tld("lc").
tld("lds").
tld("lease").
tld("leclerc").
tld("lefrak").
tld("legal").
tld("lego").
tld("lexus").
tld("lgbt").
tld("li").
tld("liaison").
tld("lidl").
tld("life").
tld("lifeinsurance").
tld("lifestyle").
tld("lighting").
tld("like").
tld("lilly").
tld("limited").
tld("limo").
tld("lincoln").
tld("linde").
tld("link").
tld("lipsy").
tld("live").
tld("living").
tld("lixil").
tld("lk").
tld("llc").
tld("llp").
tld("loan").
tld("loans").
tld("locker").
tld("locus").
tld("loft").
tld("lol").
tld("london").
tld("lotte").
tld("lotto").
tld("love").
tld("lpl").
tld("lplfinancial").
tld("lr").
tld("ls").
tld("lt").
tld("ltd").
tld("ltda").
tld("lu").
tld("lundbeck").
tld("lupin").
tld("luxe").
tld("luxury").
tld("lv").
tld("ly").
tld("ma").
tld("macys").
tld("madrid").
tld("maif").
tld("maison").
tld("makeup").
tld("man").
tld("management").
tld("mango").
tld("map").
tld("market").
tld("marketing").
tld("markets").
tld("marriott").
tld("marshalls").
tld("maserati").
tld("mattel").
tld("mba").
tld("mc").
tld("mcd").
tld("mcdonalds").
tld("mckinsey").
tld("md").
tld("me").
tld("med").
tld("media").
tld("meet").
tld("melbourne").
tld("meme").
tld("memorial").
tld("men").
tld("menu").
tld("meo").
tld("merckmsd").
tld("metlife").
tld("mg").
tld("mh").
tld("miami").
tld("microsoft").
tld("mil").
tld("mini").
tld("mint").
tld("mit").
tld("mitsubishi").
tld("mk").
tld("ml").
tld("mlb").
tld("mls").
tld("mm").
tld("mma").
tld("mn").
tld("mo").
tld("mobi").
tld("mobile").
tld("mobily").
tld("moda").
tld("moe").
tld("moi").
tld("mom").
tld("monash").
tld("money").
tld("monster").
tld("montblanc").
tld("mopar").
tld("mormon").
tld("mortgage").
tld("moscow").
tld("moto").
tld("motorcycles").
tld("mov").
tld("movie").
tld("movistar").
tld("mp").
tld("mq").
tld("mr").
tld("ms").
tld("msd").
tld("mt").
tld("mtn").
tld("mtpc").
tld("mtr").
tld("mu").
tld("museum").
tld("mutual").
tld("mutuelle").
tld("mv").
tld("mw").
tld("mx").
tld("my").
tld("mz").
tld("na").
tld("nab").
tld("nadex").
tld("nagoya").
tld("name").
tld("nationwide").
tld("natura").
tld("navy").
tld("nba").
tld("nc").
tld("ne").
tld("nec").
tld("net").
tld("netbank").
tld("netflix").
tld("network").
tld("neustar").
tld("new").
tld("newholland").
tld("news").
tld("next").
tld("nextdirect").
tld("nexus").
tld("nf").
tld("nfl").
tld("ng").
tld("ngo").
tld("nhk").
tld("ni").
tld("nico").
tld("nike").
tld("nikon").
tld("ninja").
tld("nissan").
tld("nissay").
tld("nl").
tld("no").
tld("nokia").
tld("northwesternmutual").
tld("norton").
tld("now").
tld("nowruz").
tld("nowtv").
tld("np").
tld("nr").
tld("nra").
tld("nrw").
tld("ntt").
tld("nu").
tld("nyc").
tld("nz").
tld("obi").
tld("observer").
tld("off").
tld("office").
tld("okinawa").
tld("olayan").
tld("olayangroup").
tld("oldnavy").
tld("ollo").
tld("om").
tld("omega").
tld("one").
tld("ong").
tld("onl").
tld("online").
tld("onyourside").
tld("ooo").
tld("open").
tld("oracle").
tld("orange").
tld("org").
tld("organic").
tld("orientexpress").
tld("origins").
tld("osaka").
tld("otsuka").
tld("ott").
tld("ovh").
tld("pa").
tld("page").
tld("pamperedchef").
tld("panasonic").
tld("panerai").
tld("paris").
tld("pars").
tld("partners").
tld("parts").
tld("party").
tld("passagens").
tld("pay").
tld("pccw").
tld("pe").
tld("pet").
tld("pf").
tld("pfizer").
tld("pg").
tld("ph").
tld("pharmacy").
tld("phd").
tld("philips").
tld("phone").
tld("photo").
tld("photography").
tld("photos").
tld("physio").
tld("piaget").
tld("pics").
tld("pictet").
tld("pictures").
tld("pid").
tld("pin").
tld("ping").
tld("pink").
tld("pioneer").
tld("pizza").
tld("pk").
tld("pl").
tld("place").
tld("play").
tld("playstation").
tld("plumbing").
tld("plus").
tld("pm").
tld("pn").
tld("pnc").
tld("pohl").
tld("poker").
tld("politie").
tld("porn").
tld("post").
tld("pr").
tld("pramerica").
tld("praxi").
tld("press").
tld("prime").
tld("pro").
tld("prod").
tld("productions").
tld("prof").
tld("progressive").
tld("promo").
tld("properties").
tld("property").
tld("protection").
tld("pru").
tld("prudential").
tld("ps").
tld("pt").
tld("pub").
tld("pw").
tld("pwc").
tld("py").
tld("qa").
tld("qpon").
tld("quebec").
tld("quest").
tld("qvc").
tld("racing").
tld("radio").
tld("raid").
tld("re").
tld("read").
tld("realestate").
tld("realtor").
tld("realty").
tld("recipes").
tld("red").
tld("redstone").
tld("redumbrella").
tld("rehab").
tld("reise").
tld("reisen").
tld("reit").
tld("reliance").
tld("ren").
tld("rent").
tld("rentals").
tld("repair").
tld("report").
tld("republican").
tld("rest").
tld("restaurant").
tld("review").
tld("reviews").
tld("rexroth").
tld("rich").
tld("richardli").
tld("ricoh").
tld("rightathome").
tld("ril").
tld("rio").
tld("rip").
tld("rmit").
tld("ro").
tld("rocher").
tld("rocks").
tld("rodeo").
tld("rogers").
tld("room").
tld("rs").
tld("rsvp").
tld("ru").
tld("rugby").
tld("ruhr").
tld("run").
tld("rw").
tld("rwe").
tld("ryukyu").
tld("sa").
tld("saarland").
tld("safe").
tld("safety").
tld("sakura").
tld("sale").
tld("salon").
tld("samsclub").
tld("samsung").
tld("sandvik").
tld("sandvikcoromant").
tld("sanofi").
tld("sap").
tld("sapo").
tld("sarl").
tld("sas").
tld("save").
tld("saxo").
tld("sb").
tld("sbi").
tld("sbs").
tld("sc").
tld("sca").
tld("scb").
tld("schaeffler").
tld("schmidt").
tld("scholarships").
tld("school").
tld("schule").
tld("schwarz").
tld("science").
tld("scjohnson").
tld("scor").
tld("scot").
tld("sd").
tld("se").
tld("search").
tld("seat").
tld("secure").
tld("security").
tld("seek").
tld("select").
tld("sener").
tld("services").
tld("ses").
tld("seven").
tld("sew").
tld("sex").
tld("sexy").
tld("sfr").
tld("sg").
tld("sh").
tld("shangrila").
tld("sharp").
tld("shaw").
tld("shell").
tld("shia").
tld("shiksha").
tld("shoes").
tld("shop").
tld("shopping").
tld("shouji").
tld("show").
tld("showtime").
tld("shriram").
tld("si").
tld("silk").
tld("sina").
tld("singles").
tld("site").
tld("sj").
tld("sk").
tld("ski").
tld("skin").
tld("sky").
tld("skype").
tld("sl").
tld("sling").
tld("sm").
tld("smart").
tld("smile").
tld("sn").
tld("sncf").
tld("so").
tld("soccer").
tld("social").
tld("softbank").
tld("software").
tld("sohu").
tld("solar").
tld("solutions").
tld("song").
tld("sony").
tld("soy").
tld("spa").
tld("space").
tld("spiegel").
tld("sport").
tld("spot").
tld("spreadbetting").
tld("sr").
tld("srl").
tld("srt").
tld("ss").
tld("st").
tld("stada").
tld("staples").
tld("star").
tld("starhub").
tld("statebank").
tld("statefarm").
tld("statoil").
tld("stc").
tld("stcgroup").
tld("stockholm").
tld("storage").
tld("store").
tld("stream").
tld("studio").
tld("study").
tld("style").
tld("su").
tld("sucks").
tld("supplies").
tld("supply").
tld("support").
tld("surf").
tld("surgery").
tld("suzuki").
tld("sv").
tld("swatch").
tld("swiftcover").
tld("swiss").
tld("sx").
tld("sy").
tld("sydney").
tld("symantec").
tld("systems").
tld("sz").
tld("tab").
tld("taipei").
tld("talk").
tld("taobao").
tld("target").
tld("tatamotors").
tld("tatar").
tld("tattoo").
tld("tax").
tld("taxi").
tld("tc").
tld("tci").
tld("td").
tld("tdk").
tld("team").
tld("tech").
tld("technology").
tld("tel").
tld("telecity").
tld("telefonica").
tld("temasek").
tld("tennis").
tld("teva").
tld("tf").
tld("tg").
tld("th").
tld("thd").
tld("theater").
tld("theatre").
tld("tiaa").
tld("tickets").
tld("tienda").
tld("tiffany").
tld("tips").
tld("tires").
tld("tirol").
tld("tj").
tld("tjmaxx").
tld("tjx").
tld("tk").
tld("tkmaxx").
tld("tl").
tld("tm").
tld("tmall").
tld("tn").
tld("to").
tld("today").
tld("tokyo").
tld("tools").
tld("top").
tld("toray").
tld("toshiba").
tld("total").
tld("tours").
tld("town").
tld("toyota").
tld("toys").
tld("tr").
tld("trade").
tld("trading").
tld("training").
tld("travel").
tld("travelchannel").
tld("travelers").
tld("travelersinsurance").
tld("trust").
tld("trv").
tld("tt").
tld("tube").
tld("tui").
tld("tunes").
tld("tushu").
tld("tv").
tld("tvs").
tld("tw").
tld("tz").
tld("ua").
tld("ubank").
tld("ubs").
tld("uconnect").
tld("ug").
tld("uk").
tld("unicom").
tld("university").
tld("uno").
tld("uol").
tld("ups").
tld("us").
tld("uy").
tld("uz").
tld("va").
tld("vacations").
tld("vana").
tld("vanguard").
tld("vc").
tld("ve").
tld("vegas").
tld("ventures").
tld("verisign").
tld("versicherung").
tld("vet").
tld("vg").
tld("vi").
tld("viajes").
tld("video").
tld("vig").
tld("viking").
tld("villas").
tld("vin").
tld("vip").
tld("virgin").
tld("visa").
tld("vision").
tld("vista").
tld("vistaprint").
tld("viva").
tld("vivo").
tld("vlaanderen").
tld("vn").
tld("vodka").
tld("volkswagen").
tld("volvo").
tld("vote").
tld("voting").
tld("voto").
tld("voyage").
tld("vu").
tld("vuelos").
tld("wales").
tld("walmart").
tld("walter").
tld("wang").
tld("wanggou").
tld("warman").
tld("watch").
tld("watches").
tld("weather").
tld("weatherchannel").
tld("webcam").
tld("weber").
tld("website").
tld("wed").
tld("wedding").
tld("weibo").
tld("weir").
tld("wf").
tld("whoswho").
tld("wien").
tld("wiki").
tld("williamhill").
tld("win").
tld("windows").
tld("wine").
tld("winners").
tld("wme").
tld("wolterskluwer").
tld("woodside").
tld("work").
tld("works").
tld("world").
tld("wow").
tld("ws").
tld("wtc").
tld("wtf").
tld("xbox").
tld("xerox").
tld("xfinity").
tld("xihuan").
tld("xin").
tld("xn--11b4c3d").
tld("xn--1ck2e1b").
tld("xn--1qqw23a").
tld("xn--2scrj9c").
tld("xn--30rr7y").
tld("xn--3bst00m").
tld("xn--3ds443g").
tld("xn--3e0b707e").
tld("xn--3hcrj9c").
tld("xn--3oq18vl8pn36a").
tld("xn--3pxu8k").
tld("xn--42c2d9a").
tld("xn--45br5cyl").
tld("xn--45brj9c").
tld("xn--45q11c").
tld("xn--4dbrk0ce").
tld("xn--4gbrim").
tld("xn--54b7fta0cc").
tld("xn--55qw42g").
tld("xn--55qx5d").
tld("xn--5su34j936bgsg").
tld("xn--5tzm5g").
tld("xn--6frz82g").
tld("xn--6qq986b3xl").
tld("xn--80adxhks").
tld("xn--80ao21a").
tld("xn--80aqecdr1a").
tld("xn--80asehdb").
tld("xn--80aswg").
tld("xn--8y0a063a").
tld("xn--90a3ac").
tld("xn--90ae").
tld("xn--90ais").
tld("xn--9dbq2a").
tld("xn--9et52u").
tld("xn--9krt00a").
tld("xn--b4w605ferd").
tld("xn--bck1b9a5dre4c").
tld("xn--c1avg").
tld("xn--c2br7g").
tld("xn--cck2b3b").
tld("xn--cckwcxetd").
tld("xn--cg4bki").
tld("xn--clchc0ea0b2g2a9gcd").
tld("xn--czr694b").
tld("xn--czrs0t").
tld("xn--czru2d").
tld("xn--d1acj3b").
tld("xn--d1alf").
tld("xn--e1a4c").
tld("xn--eckvdtc9d").
tld("xn--efvy88h").
tld("xn--estv75g").
tld("xn--fct429k").
tld("xn--fhbei").
tld("xn--fiq228c5hs").
tld("xn--fiq64b").
tld("xn--fiqs8s").
tld("xn--fiqz9s").
tld("xn--fjq720a").
tld("xn--flw351e").
tld("xn--fpcrj9c3d").
tld("xn--fzc2c9e2c").
tld("xn--fzys8d69uvgm").
tld("xn--g2xx48c").
tld("xn--gckr3f0f").
tld("xn--gecrj9c").
tld("xn--gk3at1e").
tld("xn--h2breg3eve").
tld("xn--h2brj9c").
tld("xn--h2brj9c8c").
tld("xn--hxt814e").
tld("xn--i1b6b1a6a2e").
tld("xn--imr513n").
tld("xn--io0a7i").
tld("xn--j1aef").
tld("xn--j1amh").
tld("xn--j6w193g").
tld("xn--jlq480n2rg").
tld("xn--jlq61u9w7b").
tld("xn--jvr189m").
tld("xn--kcrx77d1x4a").
tld("xn--kprw13d").
tld("xn--kpry57d").
tld("xn--kpu716f").
tld("xn--kput3i").
tld("xn--l1acc").
tld("xn--lgbbat1ad8j").
tld("xn--mgb9awbf").
tld("xn--mgba3a3ejt").
tld("xn--mgba3a4f16a").
tld("xn--mgba7c0bbn0a").
tld("xn--mgbaakc7dvf").
tld("xn--mgbaam7a8h").
tld("xn--mgbab2bd").
tld("xn--mgbah1a3hjkrd").
tld("xn--mgbai9azgqp6j").
tld("xn--mgbayh7gpa").
tld("xn--mgbb9fbpob").
tld("xn--mgbbh1a").
tld("xn--mgbbh1a71e").
tld("xn--mgbc0a9azcg").
tld("xn--mgbca7dzdo").
tld("xn--mgbcpq6gpa1a").
tld("xn--mgberp4a5d4ar").
tld("xn--mgbgu82a").
tld("xn--mgbi4ecexp").
tld("xn--mgbpl2fh").
tld("xn--mgbt3dhd").
tld("xn--mgbtx2b").
tld("xn--mgbx4cd0ab").
tld("xn--mix891f").
tld("xn--mk1bu44c").
tld("xn--mxtq1m").
tld("xn--ngbc5azd").
tld("xn--ngbe9e0a").
tld("xn--ngbrx").
tld("xn--node").
tld("xn--nqv7f").
tld("xn--nqv7fs00ema").
tld("xn--nyqy26a").
tld("xn--o3cw4h").
tld("xn--ogbpf8fl").
tld("xn--otu796d").
tld("xn--p1acf").
tld("xn--p1ai").
tld("xn--pbt977c").
tld("xn--pgbs0dh").
tld("xn--pssy2u").
tld("xn--q7ce6a").
tld("xn--q9jyb4c").
tld("xn--qcka1pmc").
tld("xn--qxa6a").
tld("xn--qxam").
tld("xn--rhqv96g").
tld("xn--rovu88b").
tld("xn--rvc1e0am3e").
tld("xn--s9brj9c").
tld("xn--ses554g").
tld("xn--t60b56a").
tld("xn--tckwe").
tld("xn--tiq49xqyj").
tld("xn--unup4y").
tld("xn--vermgensberater-ctb").
tld("xn--vermgensberatung-pwb").
tld("xn--vhquv").
tld("xn--vuq861b").
tld("xn--w4r85el8fhu5dnra").
tld("xn--w4rs40l").
tld("xn--wgbh1c").
tld("xn--wgbl6a").
tld("xn--xhq521b").
tld("xn--xkc2al3hye2a").
tld("xn--xkc2dl3a5ee0h").
tld("xn--y9a3aq").
tld("xn--yfro4i67o").
tld("xn--ygbi2ammx").
tld("xn--zfr164b").
tld("xperia").
tld("xxx").
tld("xyz").
tld("yachts").
tld("yahoo").
tld("yamaxun").
tld("yandex").
tld("ye").
tld("yodobashi").
tld("yoga").
tld("yokohama").
tld("you").
tld("youtube").
tld("yt").
tld("yun").
tld("za").
tld("zappos").
tld("zara").
tld("zero").
tld("zip").
tld("zippo").
tld("zm").
tld("zone").
tld("zuerich").
tld("zw").

% The part below is used for testing 
% Currently verified is being autogened 
% by a script

word("AABAA").

verified(Cert) :- 
  std:isCert(Cert).


