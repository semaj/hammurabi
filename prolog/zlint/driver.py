#!/usr/bin/env python3

# The following code is a python driver that
# can query a singlular lint rule (pass/fail) and a singular
# applies rule (NA) from a specific prolog file
# Usage: python3 driver.py [Prolog File] [Lint Rule] [Applies Rule]

import json
import sys

from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.web import JsonLexer
from pyswip import Prolog

zlint = sys.argv[1]
applies_rules = sys.argv[2]

prolog = Prolog()
prolog.consult(zlint)

results = {}
with open(applies_rules) as f:
    for line in f:
        try:
            apply, lint = line.strip().split(";")
            applies = bool(list(prolog.query(apply + "(X)")))
            if not applies:
                results[lint] = {"result": "NA"}
                continue
            passes = bool(list(prolog.query(lint + "(X)")))
            results[lint] = {"result": "pass" if passes else "fail"}
        except:
            pass


output = json.dumps(results, indent=2)
print(highlight(output, lexer=JsonLexer(), formatter=Terminal256Formatter()))
