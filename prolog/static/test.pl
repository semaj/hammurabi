#!/usr/bin/env swipl

:- use_module(library(uri)).

cleanName(Name, Decoded) :-
  uri_encoded(path, Decoded, Name),
  sub_string(Decoded, _, 1, 0, LastChar),
  LastChar \= ".",
  write("cleaned1:"),
  write(Decoded),
  write("\n").

cleanName(Name, Cleaned) :-
  uri_encoded(path, Decoded, Name),
  sub_string(Decoded, _, 1, 0, LastChar),
  LastChar = ".",
  sub_string(Decoded, 0, _, 1, Cleaned),
  write("cleaned2:"),
  write(Cleaned),
  write("\n").
