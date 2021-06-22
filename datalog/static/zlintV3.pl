:- use_module(certs).
:- use_module(std).
:- use_module(env).

% sub_ca_cert: ca field MUST be set to true.
caIsCa(Cert) :-
  certs:isCA(Cert, true).
  
% sub_ca_cert: basicConstraints MUST be present & marked critical.
basicConstaintsMustBeCritical(Cert) :-
  certs:basicConstraintsExt(Cert, true),
  certs:basicConstraintsCritical(Cert, true).
  
% sub_ca_cert: crl DistPoint MUST be present & NOT marked critical.

%   certs:fingerprint(Cert, Fingerprint),
%   crl_set(Fingerprint).
  
