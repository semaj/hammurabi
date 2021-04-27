from collections import defaultdict
from pyparsing import *

SimpleFields = ("BasicConstraints0",)
ListFields = ("KeyUsage",)

def topological_sort(graph, start):
    seen = set()
    stack = []    # path variable is gone, stack and order are new
    order = []    # order will be in reverse order at first
    q = [start]
    while q:
        v = q.pop()
        if v not in seen:
            seen.add(v) # no need to append to path any more
            q.extend(graph[v])

            while stack and v not in graph[stack[-1]]: # new stuff here!
                order.append(stack.pop())
            stack.append(v)

    return stack + order[::-1]   # new return value!

def fix_head_clause(head_clause, to_put):
    if type(head_clause['terms']) != set:
        terms = map(lambda t: next(iter(t.values()))[0], head_clause['terms'])
        head_clause['terms'] = set(terms)
        head_clause['terms'].remove('Cert')
    head_clause['terms'].add(to_put)

def fix_rule(rule):
    for i, clause in enumerate(rule['clauses']):
        if len(clause['predicate']['atoms']) == 2 and clause['predicate']['atoms'][0] == "certs":
            field = clause['predicate']['atoms'][1]
            field = field[0].upper() + field[1:]
            value = clause['terms'][1]['atoms'][0]
            if field in SimpleFields:
                fix_head_clause(rule['head_clause'], field)
                rule['clauses'][i] = f"{field} = {value}"
            elif field in ListFields:
                fix_head_clause(rule['head_clause'], field)
                if value == "none":
                    rule['clauses'][i] = f"{field} = []"
                else:
                    rule['clauses'][i] = f"member({value}, {field})"

def dump_clause(clause):
    if type(clause) == str:
        return clause
    if type(clause['terms']) == set:
        terms = clause['terms']
    else:
        terms = map(lambda t: next(iter(t.values()))[0], clause['terms'])
    return "".join([
        ":".join(clause['predicate']['atoms']),
        "(",
        ",".join(terms),
        ")"
    ])

def dump_rule(rule):
    return "".join([
        dump_clause(rule['head_clause']),
        ":-\n\t",
        ",\n\t".join(map(dump_clause, rule['clauses'])),
        "."
    ])

def dump_fact(fact):
    return dump_clause(fact['clauses'][0]) + "."

number = Word(nums)("ints*")
atom = Word(alphas.lower(), alphanums)("atoms*")
variable = Word(alphas.upper(), alphanums)("variables*")
term = Group(number | atom | variable)('terms*')

predicate = Group(Optional(atom + Suppress(':')) + atom)('predicate')
# arguments= Group(Suppress('(') + delimitedList(term) + Suppress(')'))('arguments*')

head_clause = Group(predicate + Suppress('(') + delimitedList(term) + Suppress(')') + Suppress(':') + Suppress('-'))('head_clause')
clause = Group(predicate + Suppress('(') + delimitedList(term) + Suppress(')'))('clauses*')

fact = Group(clause + Suppress('.'))('facts*')
rule = Group(head_clause + delimitedList(clause) + Suppress('.'))('rules*')

sentence = fact | rule

prolog = OneOrMore(sentence)

toparse = """
certs:basicConstraints0(Cert, true).

std:isCA(Cert):-
    certs:basicConstraints0(Cert, true).

certs:keyUsage(Cert, serverAuth).
checkKeyUsage(Cert):-
    certs:keyUsage(Cert, none).

checkKeyUsage(Cert):-
    std:isCA(Cert), certs:keyUsage(Cert, keyCertSign).
"""

code = prolog.parseString(toparse, parseAll=True).asDict()
nodes = defaultdict(list)
for rule in code['rules']:
    nodes[":".join(rule['head_clause']['predicate']['atoms'])].append(rule)

adj = defaultdict(list)
for a, rules in nodes.items():
    for rule in rules:
        for b in rule['clauses']:
            b = ":".join(b['predicate']['atoms'])
            if b in nodes:
                adj[b].append(a)

graph = {n: adj[n] for n in nodes}
sorted = topological_sort(graph, next(iter(nodes)))
print(sorted)



for fact in code['facts']:
    print(dump_fact(fact))

for rule in code['rules']:
    fix_rule(rule)
    print(dump_rule(rule))
    # fix_rule(rule)
    
