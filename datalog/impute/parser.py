#! /usr/bin/env python3
import sys
from collections import defaultdict

from pyparsing import *

SimpleFields = ("BasicConstraints0",)
ListFields = ("KeyUsage",)


def topo_sort(nodes, adj):
    output = []
    fresh = set(nodes.keys())

    def dfs(node):
        fresh.remove(node)
        for child in adj[node]:
            if child in fresh:
                dfs(child)
        output.append(node)

    for node in nodes:
        if node in fresh:
            dfs(node)
    return output


########### Transformation methods #############################################
def fix_head_clause(head_clause, to_put):
    if type(head_clause["terms"]) != set:
        terms = map(lambda t: next(iter(t.values()))[0], head_clause["terms"])
        head_clause["terms"] = set(terms)
        head_clause["terms"].remove("Cert")
    head_clause["terms"].add(to_put)


def fix_rule(rule):
    for i, clause in enumerate(rule["clauses"]):
        if (
            len(clause["predicate"]["atoms"]) == 2
            and clause["predicate"]["atoms"][0] == "certs"
        ):
            field = clause["predicate"]["atoms"][1]
            field = field[0].upper() + field[1:]
            value = clause["terms"][1]["atoms"][0]
            if field in SimpleFields:
                fix_head_clause(rule["head_clause"], field)
                rule["clauses"][i] = f"{field} = {value}"
            elif field in ListFields:
                fix_head_clause(rule["head_clause"], field)
                if value == "none":
                    rule["clauses"][i] = f"{field} = []"
                else:
                    rule["clauses"][i] = f"member({value}, {field})"


########### Print methods ######################################################
def dump_clause(clause):
    if type(clause) == str:
        return clause
    if type(clause["terms"]) == set:
        terms = clause["terms"]
    else:
        terms = map(lambda t: next(iter(t.values()))[0], clause["terms"])
    return "".join([":".join(clause["predicate"]["atoms"]), "(", ",".join(terms), ")"])


def dump_rule(rule):
    return "".join(
        [
            dump_clause(rule["head_clause"]),
            ":-\n\t",
            ",\n\t".join(map(dump_clause, rule["clauses"])),
            ".",
        ]
    )


def dump_fact(fact):
    return dump_clause(fact["clauses"][0]) + "."


########### Parser patterns ####################################################
comment = ("%" + restOfLine).suppress()
number = Word(nums + "-")("ints*")
atom = Word(alphas.lower(), alphanums + "_")("atoms*")
variable = Word(alphas.upper(), alphanums)("variables*")
term = Group(number | atom | variable | QuotedString('"'))("terms*")
arity = atom + "/" + Word(nums)
arity_list = "[" + delimitedList(arity) + "]"
module_directive = LineStart() + ":-" + "module" + "(" + term + "," + arity_list + ")."
other_directive = LineStart() + ":-" + term + OneOrMore(~("." | LineEnd())) + "."
directive = module_directive | other_directive

predicate = Group(Optional("\+") + Optional(atom + Suppress(":")) + atom)("predicate")
# arguments= Group(Suppress('(') + delimitedList(term) + Suppress(')'))('arguments*')

head_clause = Group(
    predicate
    + Suppress("(")
    + delimitedList(term)
    + Suppress(")")
    + Suppress(":")
    + Suppress("-")
)("head_clause")
clause = Group(predicate + Suppress("(") + delimitedList(term) + Suppress(")"))(
    "clauses*"
)

fact = Group(clause + Suppress("."))("facts*")
rule = Group(head_clause + delimitedList(clause) + Suppress("."))("rules*")

sentence = fact | rule | directive
prolog = OneOrMore(sentence)

########### Transformation #####################################################
if __name__ == "__main__":
    # read input file
    # sys.argv = ["", "transform.pl"]
    with open(sys.argv[1]) as f:
        toparse = comment.transformString(f.read())

    code = prolog.parseString(toparse, parseAll=True).asDict()
    print("parsed")

    # build graph for topological sort
    nodes = defaultdict(list)
    for rule in code["rules"]:
        nodes[":".join(rule["head_clause"]["predicate"]["atoms"])].append(rule)

    adj = defaultdict(list)
    for a, rules in nodes.items():
        for rule in rules:
            for b in rule["clauses"]:
                b = ":".join(b["predicate"]["atoms"])
                if b in nodes:
                    adj[b].append(a)

    sorted_preds = topo_sort(nodes, adj)

    # fix rules
    for pred in sorted_preds:
        for rule in nodes[pred]:
            fix_rule(rule)
            print(dump_rule(rule))
