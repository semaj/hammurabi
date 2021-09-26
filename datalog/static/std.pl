:- module(std, [
    stringMatch/2,
    nameMatchesSAN/2,
    nameMatchesCN/2,
    isTimeValid/2,
    isCA/1,
    isEV/2,
    getBasicConstraints/2
]).

:- use_module(library(dialect/sicstus/system)).
:- use_module(library(clpfd)).


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
nameMatchesSAN(Domain, SANList):-
    member(SAN, SANList),
    stringMatch(SAN, Domain).

nameMatchesCN(Domain, Subject):-
    stringMatch(Subject, Domain).

% time validity check. between Lower and Upper
isTimeValid(Lower, Upper):-
    % now(T),
    T = 1621487267,
    Lower #< T, Upper #> T.

% Basic Constraints checks
% CA bit set
isCA(BasicConstraints):-
    BasicConstraints = [true, _].

isEV(CertPolicies, RootSubject):-
    CertPolicies = [Oid, _],
    types:evPolicyOid(Oid, RootSubject).

getBasicConstraints(Cert, BasicConstraints):-
    certs:basicConstraintsExt(Cert, false),
    BasicConstraints = [].

getBasicConstraints(Cert, BasicConstraints):-
    certs:basicConstraintsExt(Cert, true),
    certs:isCA(Cert, IsCA),
    certs:pathLimit(Cert, PathLimit),
    BasicConstraints = [IsCA, PathLimit].