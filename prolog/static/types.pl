:- module(types, [
    sanList/1,
    timestamp/1,
    md2_sig_algo/1,
    md4_sig_algo/1,
    md5_sig_algo/1,
    sha1_sig_algo/1,
    algorithm/1,
    basicConstraints/1,
    keyUsageList/1,
    extKeyUsageList/1,
    stapledResponse/1,
    ocspResponse/1,
    evStatus/1
]).
:- use_module(library(clpfd)).

sanList(L):-
    N in 0..4, label([N]), length(L, N).

epoch_start(631170000).                 % 01-01-1990 00:00:00
epoch_end(2524626000).                  % 01-01-2050 00:00:00

timestamp(T):-
    epoch_start(Start),
    epoch_end(End),
    T in Start..End.

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
  
% ecdsa
ecdsa_sig_algo("1.2.840.10045.4.3.2").% ECDSA + SHA512
ecdsa_sig_algo("1.2.840.10045.4.3.3").  % ECDSA + SHA384
ecdsa_sig_algo("1.2.840.10045.4.3.4").  % ECDSA + SHA512

% rsa
rsa_sig_algo("1.2.840.113549.1.1.11").  % RSA + SHA256
rsa_sig_algo("1.2.840.113549.1.1.12").  % RSA + SHA384
rsa_sig_algo("1.2.840.113549.1.1.13").  % RSA + SHA512
rsa_sig_algo("1.2.840.113549.1.1.10").  % RSA-PSS + SHA256

algorithm(Oid):-
  md2_sig_algo(Oid);
  md4_sig_algo(Oid);
  md5_sig_algo(Oid);
  sha1_sig_algo(Oid);
  ecdsa_sig_algo(Oid);
  rsa_sig_algo(Oid).

basicConstraints(Bc):-
    Bc = [];
    (
        Bc = [Ca, Len],
        (Ca = true; Ca = false),
        Len in 0..10
    ).

keyUsageVal(digitalSignature).
keyUsageVal(keyEncipherment).
keyUsageVal(keyAgreement).
keyUsageVal(keyCertSign).

keyUsageList(L):-
  N in 0..4, label([N]), length(L, N),
  maplist(keyUsageVal, L), is_set(L).
  
extKeyUsageVal(any).
extKeyUsageVal(serverAuth).
extKeyUsageVal(clientAuth).
extKeyUsageVal(oCSPSigning).

extKeyUsageList(L):-
  N in 0..2, label([N]), length(L, N),
  maplist(extKeyUsageVal, L), is_set(L).

stapledResponse(Response):-
  Response = [].

stapledResponse(Response):-
  Response = [A, B, C, D],
  (A = valid; A = invalid),
  (B = expired; B = not_expired),
  (C = verified; C = not_verified),
  (D = good; C = revoked).

ocspResponse(Response):-
  stapledResponse(Response).

evStatus(EVStatus):-
  EVStatus = ev; EVStatus = not_ev.
