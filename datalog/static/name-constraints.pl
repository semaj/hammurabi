:- use_module(ext).
:- use_module(certs).

permittedSubtree("jameslarisch.com").

certViolatesNameConstraint(Cert):-
  permittedSubtree(Suffix),
  certs:san(Cert, Name),
  \+ext:s_endswith(Name, Suffix).

check(Cert) :-
  \+certViolatesNameConstraint(Cert).

% Query: verified(cert_0)?
