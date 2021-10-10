:- module(std, [
    stringMatch/2,
    nameMatchesSAN/2,
    nameMatchesCN/2,
    isTimeValid/2,
    isCA/1,
    getBasicConstraints/2
]).

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

count(L, E, N) :-
    include(=(E), L, L2), length(L2, N).

% stringMatch(PatternStr, CommonNameStr):-
%     var(CommonName),
%     string_chars(PatternStr, Pattern),
%     string_chars(CommonNameStr, CommonName),
%     Pattern = ['*' , '.' | ToMatch],
%     nth1(1, ToMatch, _),
%     ( CommonName = ToMatch; (
%         append(Prefix, ['.' | ToMatch], CommonName),
%         nth1(1, Prefix, _)
%     )).

stringMatch(PatternStr, CommonNameStr):-
    string_chars(PatternStr, Pattern),
    string_chars(CommonNameStr, CommonName),
    Pattern = ['*' , '.' | ToMatch],
    nth1(1, ToMatch, _),
    ( CommonName = ToMatch; (
        append(Prefix, ['.' | ToMatch], CommonName),
        nth1(1, Prefix, _),
        \+member('.', Prefix)
    )).

stringMatch(PatternStr, CommonNameStr):-
    CommonName = Pattern,
    string_chars(PatternStr, Pattern),
    string_chars(CommonNameStr, CommonName),
    Pattern \= ['*' , '.' | _].

% domain name matches one of the names in SAN
nameMatchesSAN(Domain, SANList):-
    member(SAN, SANList),
    stringMatch(SAN, Domain).

nameMatchesCN(Domain, Subject):-
    stringMatch(Subject, Domain).

% time validity check. between Lower and Upper
isTimeValid(Lower, Upper):-
    % now(T),
    T = 1601603624,
    Lower < T, Upper > T.

% Basic Constraints checks
% CA bit set
isCA(BasicConstraints):-
    BasicConstraints = [true, _].

getBasicConstraints(Cert, BasicConstraints):-
    certs:basicConstraintsExt(Cert, false),
    BasicConstraints = [].

getBasicConstraints(Cert, BasicConstraints):-
    certs:basicConstraintsExt(Cert, true),
    certs:isCA(Cert, IsCA),
    certs:pathLimit(Cert, PathLimit),
    BasicConstraints = [IsCA, PathLimit].
