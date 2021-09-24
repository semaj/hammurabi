% ...
:- module(ext, [
    unequal/2,
    equal/2,
    add/3,
    subtract/3,
    s_endswith/2,
    s_startswith/2,
    s_substring/4,
    b_lshift/3,
    b_and/3,
    now/1
]).

unequal(X, Y):-
    X \== Y.

equal(X, Y):-
    X == Y.

larger(X, Y):-
    X > Y.

geq(X, Y):-
    X >= Y.

add(X, Y, Z):-
    X = Y + Z.

subtract(X, Y, Z):-
    X = Y - Z.

s_endswith(String, Suffix):-
    string_concat(_, Suffix, String).

s_startswith(String, Prefix):-
    string_concat(Prefix, _, String).

s_substring(String, Before, After, SubString):-
    sub_string(String, Before, _, After, SubString).

s_occurrences(String, Char, N) :-
    aggregate_all(count, sub_atom(String, _,_,_, Char), N).

b_lshift(X, Y, Z):-
    X = Y << Z.

b_and(X, Y, Z):-
    X = Y /\ Z.

now(T):-
    get_time(T).
