#!/bin/sh

MODULE=`basename $1 .pl`
MODULE=`echo $MODULE | sed -E "s/certs[[:digit:]]+/certs/g"`
MODULE=`echo $MODULE | sed -E "s/checks[[:digit:]]+/checks/g"`

SPACE="[[:blank:]]"

ATOM="[A-Za-z0-9\_]+"
STRING="\".*\""

# term = space + number or atom or string
TERM="$SPACE*(\-?[0-9\.]+|$ATOM|$STRING)"


# sed -E replace " some_atom(term1, term2, ...)" with " module:some_atom(term1, term2, ...)"
#        replace "<begin-line>some_atom(term1, term2, ...)" with "module:some_atom(term1, term2, ...)"
#        replace "<begin-line> pred/arity, " with ""
#        replace "<begin-line> ])." with ""
#        replace "<begin-line>:- <anything>" with ""

sed -E "s/(,*$SPACE+)(\\\\\+)?($ATOM\($TERM(,$TERM)*\))/\1\2$MODULE:\3/g;
        s/^(\\\\\+)?($ATOM\($TERM(,$TERM)*\))/\1$MODULE:\2/g;
        s/^$SPACE*$ATOM\/[0-9]+\,?$SPACE*$//g;
        s/^$SPACE*\]\)\.$//g;
        s/^:\-.*$//g;
        s/[@]:\-$SPACE$MODULE:/\:\-/g;" $1
