:- module(std, [
    stringMatch/2,
    nameMatchesSAN/1,
    nameMatchesCN/1,
    nameMatches/2,
    isTimeValid/2,
    extendedKeyUsageExpected/3,
    isRoot/1,
    isCA/1,
    isNotCA/1,
    pathLengthOkay/3,
    maxIntermediatesOkay/1,
    algorithm/1
]).

:- use_module(env).
:- use_module(library(dialect/sicstus/system)).
:- use_module(library(clpfd)).

:- set_prolog_flag(double_quotes, chars).

stringMatch(Pattern, CommonName):-
    var(CommonName),
    Pattern = ['*' , '.' | ToMatch],
    nth1(1, ToMatch, _),
    ( CommonName = ToMatch; (
        append(Prefix, ['.' | ToMatch], CommonName),
        nth1(1, Prefix, _)
    )).

stringMatch(Pattern, CommonName):-
    nonvar(CommonName),
    Pattern = ['*' , '.' | ToMatch],
    nth1(1, ToMatch, _),
    ( CommonName = ToMatch; (
        append(Prefix, ['.' | ToMatch], CommonName),
        nth1(1, Prefix, _),
        \+member('.', Prefix)
    )).

stringMatch(Pattern, CommonName):-
    CommonName = Pattern,
    Pattern \= ['*' , '.' | _].

% domain name matches one of the names in SAN
nameMatchesSAN(SANList):-
    env:domain(D),
    member(SAN, SANList),
    stringMatch(SAN, D).

nameMatchesCN(Subject):-
    env:domain(D),
    stringMatch(Subject, D).

% domain name matches any
nameMatches(SAN, Subject):-
  nameMatchesSAN(SAN); nameMatchesCN(Subject).

epoch_start(631170000).                 % 01-01-1990 00:00:00
epoch_end(2524626000).                  % 01-01-2050 00:00:00

% time validity check. between Lower and Upper
isTimeValid(Lower, Upper):-
    now(T),
    epoch_start(Start),
    epoch_end(End),
    Lower #> Start,
    Upper #< End,
    T #> Lower,
    Upper #> T.

extendedKeyUsageExpected(ExtUseList, Usage, Expected):-
    Expected = 1,
    member(Usage, ExtUseList).

extendedKeyUsageExpected(ExtUseList, Usage, Expected):-
    Expected = 0,
    \+member(Usage, ExtUseList).

% check if Cert is a trusted root
isRoot(Fingerprint):-
    env:trusted_roots(Fingerprint).

% Basic Constraints checks
% CA bit set
isCA(BasicConstraints):-
    BasicConstraints = [1, _].

isNotCA(BasicConstraints):-
    BasicConstraints = none;
    BasicConstraints = [0, _].

% Path length is okay if the extension doesn't exist
pathLengthOkay(BasicConstraints, ChainLen, SelfCount) :-
    BasicConstraints = none;
    BasicConstraints = [_, none];
    (
        BasicConstraints = [_, Limit],
        Limit > ChainLen - SelfCount 
    ).

% Custom limit on intermediate certs check
% exempts trusted certs from limit
maxIntermediatesOkay(ChainLen):-
    env:max_intermediates(M),
    M > ChainLen.

% md2
md2_sig_algo("1.2.840.113549.1.1.2").
md2_sig_algo("1.3.14.7.2.3.1").

% md4
md4_sig_algo("1.2.840.113549.1.1.3").
md4_sig_algo("1.3.14.3.2.2").
md4_sig_algo("1.3.14.3.2.4").

% md5
md5_sig_algo("1.2.840.113549.1.1.4").
md5_sig_algo("1.3.14.3.2.3").
md5_sig_algo("1.2.840.113549.2.5").

% sha1
sha1_sig_algo("1.2.840.113549.1.1.5"). % sha1RSA
sha1_sig_algo("1.2.840.10040.4.3"). % sha1DSA
sha1_sig_algo("1.3.14.3.2.29"). % sha1RSA
sha1_sig_algo("1.3.14.3.2.13"). % sha1DSA
sha1_sig_algo("1.3.14.3.2.27"). % dsaSHA1
sha1_sig_algo("1.3.14.3.2.26"). % sha1NoSign
sha1_sig_algo("1.2.840.10045.4.1"). % sha1ECDSA

algorithm(Oid):-
    md2_sig_algo(Oid);
    md4_sig_algo(Oid);
    md5_sig_algo(Oid);
    sha1_sig_algo(Oid).