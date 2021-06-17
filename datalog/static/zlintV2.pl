:- use_module(std).
:- use_module(certs).

%includes zlint tests made into prolog rules

%checks if rule is applicable
caKeyUsageCriticalApplies(Cert) :-
	certs:isCA(Cert).

%if not applicable pass
caKeyUsageCritical(Cert) :-
	\+caKeyUsageCriticalApplies(Cert).

%All CA Cert: keyUsage ext must be present and marked critical (21,35)
%checked CA certs for keyUsage extension and that it is marked critical
caKeyUsageCritical(Cert) :-
	certs:keyUsageExt(Cert, true),
	certs:keyUsageCritical(Cert, true).


%cert policies must be present and not marked critical (39)
%checkes subCA for certificate policies and if they are marked critical
isSubCA(Cert) :-
	certs:isCA(Cert),
	\+std:isRoot(Cert).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	certs:certificatePoliciesExt(Cert, true),
	certs:certificatePoliciesCritical(Cert, false).

subCaCertPoliciesNotMarkedCritical(Cert) :-
	\+isSubCA(Cert).


%Root ca: basic constraint must appear as critical extension (18)
%Checks that root CA basic constraints are critical
rootApplies(Cert) :-
	certs:isCA(Cert),
	std:isRoot(Cert).

basicConstraintsCritical(Cert) :-
	certs:basicConstraintsExt(Cert, true),
	certs:basicConstraintsCritical(Cert, true).

basicConstraintsCritical(Cert) :-
	\+rootApplies(Cert).


%Root CA: path length constraint field should not be present (20)
%Checks root CA for no length constraint
rootPathLenNotPresent(Cert) :-
	certs:pathLimit(Cert, none).

rootPathLenNotPresent(Cert) :-
	\+rootApplies(Cert).

%checks that root certificate extended key usage is not present (24)
rootExtKeyUseNotPresent(Cert) :-
	certs:extendedKeyUsageExt(Cert, false).

rootExtKeyUseNotPresent(Cert) :-
	\+rootApplies(Cert).

%rules are tested here
verified(Cert) :-
	std:isCert(Cert),
	%caKeyUsageCritical(Cert).

	rootExtKeyUseNotPresent(Cert).
	%rootPathLenNotPresent(Cert).
	%basicConstraintsCritical(Cert).
	%certs:isCA(Cert).
	%subCaCertPoliciesNotMarkedCritical(Cert).

	%certs:san(Cert, Name),
	%certs:isCA(Cert, Boolean),
	%std:stringMatch("*.google.com", "www.google.com").
	%ext:s_endswith(Name, ".com").
