:- module(checks, [
  timeValidCheckEnabled/1,
  nssNameConstraintCheckEnabled/1,
  revokedCheckEnabled/1,
  chainLengthCheckEnabled/1,
  parentNotCACheckEnabled/1,
  domainMatchCheckEnabled/1,
  aCCCheckEnabled/1,
  leafValidityCheckEnabled/1
]).
timeValidCheckEnabled(true).
nssNameConstraintCheckEnabled(true).
revokedCheckEnabled(true).
chainLengthCheckEnabled(true).
parentNotCACheckEnabled(true).
domainMatchCheckEnabled(true).
aCCCheckEnabled(true).
leafValidityCheckEnabled(true).
