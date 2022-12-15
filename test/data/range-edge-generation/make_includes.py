"""
Script to convert the MongoDB server test vector #include files into their
C-equivalent counterpart
"""

from __future__ import annotations
import itertools

import sys
import re
from typing import Generic, Iterable, NamedTuple, Sequence, Tuple, Union, TypeVar

T = TypeVar('T')


class Number(NamedTuple):
    "A numeric literal (integer or float)"
    spell: str

    def __str__(self) -> str:
        return self.spell


class String(NamedTuple):
    "A quoted string literal"
    spell: str

    def __str__(self) -> str:
        return self.spell


class Ident(NamedTuple):
    "An identifier"
    spell: str

    def __str__(self) -> str:
        return self.spell


class TmplIdent(NamedTuple):
    name: str
    targs: Sequence[Expression]

    def __str__(self) -> str:
        return f'{self.name}<{", ".join(map(str, self.targs))}>'


class PrefixExpr(NamedTuple):
    "A unary prefix expression"
    operator: str
    operand: Expression

    def __str__(self) -> str:
        return f'{self.operator}{self.operand}'


class CallExpr(NamedTuple):
    "A call expression"
    fn: Expression
    args: Sequence[Expression]

    def __str__(self) -> str:
        return f'{self.fn}<{", ".join(map(str, self.args))}>'


class ScopeExpr(NamedTuple):
    "A scope-resolution '::' infix expression"
    left: Expression
    name: Ident | TmplIdent

    def __str__(self) -> str:
        return f'{self.left}::{self.name}'


class InitList(NamedTuple):
    "A braced initializer-list"
    elems: Sequence[Expression]

    def __str__(self) -> str:
        return f'{{{", ".join(map(str, self.elems))}}}'


Expression = Union[PrefixExpr, CallExpr, String, Number, InitList, ScopeExpr,
                   TmplIdent, Ident]
"An arbitrary expression (from a small subset of C++)"


class EdgeInfo(NamedTuple):
    "Edge information from a C++ #include file"
    func: Expression
    "The function that is used to generate the edge"
    value: Expression
    "The expression given as the first value"
    min: Expression
    "The min value for the edge"
    max: Expression
    "The max value for the edge"
    sparsity: Expression
    "The sparsity of the edge"
    precision: Expression
    "The precision of the edge"
    edges: Expression
    "The edges given for the test"


class Token(NamedTuple):
    "A token consumed from the input"
    spell: str
    line: int

    @property
    def isid(self) -> bool:
        """Is this an identifier?"""
        return IDENT_RE.match(self.spell) is not None

    @property
    def isnum(self) -> bool:
        """Is this a number?"""
        return NUM_RE.match(self.spell) is not None

    @property
    def isstr(self) -> bool:
        """Is this a string literal?"""
        return STRING_RE.match(self.spell) is not None

    def __repr__(self) -> str:
        return f'<Token "{self.spell}" at line {self.line}>'


IDENT_RE = re.compile(r'^[a-zA-Z_]\w*')
"Matches a C identifier"
NUM_RE = re.compile(r'^((\d+\.(\d+)?|\.\d+)f?|\d+)')
"Matches a base10 numeric literal"
STRING_RE = re.compile(r'"(\\.|[^"])*"')
"Matches a string literal"


def tokenize(code: str) -> Iterable[Token]:
    "Extract the tokens from the given code"
    code = code.lstrip()
    skipped = code[:-len(code)]
    line = skipped.count('\n') + 1
    while code:
        mat = IDENT_RE.match(code) or NUM_RE.match(code) or STRING_RE.match(
            code)
        if mat:
            idn = mat[0]
            yield Token(idn, line)
            code = code[len(idn):]
        elif code.startswith('::'):
            yield Token(code[:2], line)
            code = code[2:]
        elif code[0] in ',&{}[]().-<>':
            yield Token(code[0], line)
            code = code[1:]
        else:
            raise RuntimeError(
                f'Unknown token at "{code[:min(len(code), 30)]}"')
        code = code.lstrip()
        line += code[:-len(code)].count('\n')


class LazyList(Generic[T]):

    def __init__(self, it: Iterable[T]) -> None:
        self._iter = iter(it)
        self._acc: list[T | None] = []

    def at(self, n: int) -> T | None:
        "Obtain the Nth element from the sequence, or 'None' if at the end"
        while n >= len(self._acc):
            # We need to add to the list. Append 'None' if there's nothing left
            self._acc.append(next(self._iter, None))
        return self._acc[n]

    def adv(self, n: int = 1) -> None:
        "Discard N elements from the beginning of the list"
        self._acc = self._acc[n:]


Tokenizer = LazyList[Token]
"A token-consumer sequence"


def parse_ilist(toks: Tokenizer) -> Expression:
    "Parse a braced init-list, e.g. {1, 2, 3}"
    lbr = toks.at(0)
    assert lbr and lbr.spell == '{', f'Expected left-brace "{{" (Got {lbr=})'
    toks.adv()
    acc: list[Expression] = []
    while 1:
        peek = toks.at(0)
        assert peek, f'Unexpected EOF parsing init-list'
        # If we see a closing brace, that's the end
        if peek.spell == '}':
            toks.adv()
            break
        # Expect an element:
        expr = parse_expr(toks)
        acc.append(expr)
        peek = toks.at(0)
        assert peek, f'Unexpected EOF parsing init-list'
        # We expect either a comma or a closing brace:
        assert peek.spell in (
            '}', ','
        ), f'Expected comma or closing brace following init-list element (Got "{peek=}")'
        if peek.spell == ',':
            # Just skip the comma
            toks.adv()
    return InitList(acc)


def parse_call_args(toks: Tokenizer,
                    open: str = '(',
                    close: str = ')') -> Sequence[Expression]:
    "Parse the argument list of a function/template call."
    lpar = toks.at(0)
    assert lpar and lpar.spell == open, f'Expected opening "{open}" (Got {lpar=})'
    toks.adv()
    acc: list[Expression] = []

    peek = toks.at(0)
    while peek and peek.spell != close:
        # Parse an argument:
        x = parse_expr(toks)
        acc.append(x)
        # We expect either a comma or a closing paren next:
        peek = toks.at(0)
        assert peek, 'Unexpected EOF following argument in call expression'
        assert peek.spell in (
            ',', close
        ), f'Expected comma or "{close}" following argument (Got "{peek.spell}")'
        # Skip over the comma, if present
        if peek.spell == ',':
            # Consume the comma:
            toks.adv()
    assert peek and peek.spell == close
    toks.adv()
    return acc


def parse_nameid(toks: Tokenizer) -> Ident | TmplIdent:
    idn = toks.at(0)
    assert idn and idn.isid, f'Expected identifier beginning a nameid (Got {idn=}'
    toks.adv()
    angle = toks.at(0)
    if not angle or angle.spell != '<':
        return Ident(idn.spell)
    targs = parse_call_args(toks, '<', '>')
    return TmplIdent(idn.spell, targs)


def parse_expr(toks: Tokenizer) -> Expression:
    "Parse an arbitrary expression"
    peek = toks.at(0)
    assert peek, f'Unexpected EOF when expected an expression'
    x: Expression
    if peek.spell == '{':
        x = parse_ilist(toks)
    elif peek.spell in '-&':
        toks.adv()
        oper = parse_expr(toks)
        x = PrefixExpr(peek.spell, oper)
    elif peek.isid:
        x = parse_nameid(toks)
    elif peek.isnum:
        x = Number(peek.spell)
        toks.adv()
    elif peek.isstr:
        x = String(peek.spell)
        toks.adv()
    else:
        raise RuntimeError(f'Unknown expression beginning with token "{peek}"')
    # Look ahead for suffix expressions
    peek = toks.at(0)
    while peek and peek.spell in ('::', '('):
        if peek.spell == '(':
            args = parse_call_args(toks)
            x = CallExpr(x, args)
        elif peek.spell == '::':
            toks.adv()
            name = parse_nameid(toks)
            x = ScopeExpr(x, name)
        else:
            assert False, f'Unreachable? {peek=}'
        peek = toks.at(0)
    return x


def parse_edges(toks: Tokenizer) -> Iterable[EdgeInfo]:
    "Parse the edges from the given sequence of C++ tokens"
    while toks.at(0):
        ilist = parse_expr(toks)
        assert isinstance(ilist, InitList), ilist
        fn, val, lb, ub, sparse, edges = ilist.elems
        yield EdgeInfo(
            fn,
            val,
            lb,
            ub,
            sparse,
            # Edges do not (yet) provide precision:
            ScopeExpr(Ident('boost'), Ident('none')),
            edges,
        )
        peek = toks.at(0)
        assert peek and peek.spell == ',', f'Expect a comma following edge element'
        toks.adv()


def _render_limit(typ: Expression, limit: Ident) -> Iterable[str]:
    if isinstance(typ, ScopeExpr) and str(typ.left) == 'std':
        typ = typ.name
    assert isinstance(typ,
                      Ident), f'Unimplemented type for numeric limits {typ=}'
    mapping: dict[tuple[str, str], Expression] = {
        ('int32_t', 'min'): Ident('INT32_MIN'),
        ('int64_t', 'min'): Ident('INT64_MIN'),
        ('double', 'min'): Ident('DBL_MIN'),
    }
    e = mapping[(typ.spell, limit.spell)]
    yield from _render_expr(e)


def _render_call(c: CallExpr) -> Iterable[str]:
    base = c.fn
    # Intercept calls to numeric_limits:
    if isinstance(base, ScopeExpr) and c.args == []:
        par = base.left
        if (isinstance(par, ScopeExpr)  #
                and str(par.left) == 'std'  #
                and isinstance(par.name, TmplIdent)  #
                and par.name.name == 'numeric_limits'):
            # We're looking for numeric limits
            assert isinstance(base.name, Ident), f'Unimplemented limit: {c=}'
            yield from _render_limit(par.name.targs[0], base.name)

    # Intercept calls to "Decimal128"
    elif base == Ident('Decimal128'):
        assert len(c.args) == 1, f'Too many args for Decimal128? {c.args=}'
        arg = c.args[0]
        if isinstance(arg, Number) and '.' not in arg.spell:
            # We can convert from an integer driectly
            yield from _render_call(CallExpr(Ident('MC_DEC128'), [arg]))
        else:
            assert isinstance(
                arg,
                (Number,
                 PrefixExpr)), f'Unimplemented argument to Decimal128: {arg=}'
            # Wrap the argument in a string, since a double literal may lose precision and generate an incorrect value:
            call = CallExpr(Ident('mc_dec128_from_string'), [String(str(arg))])
            yield from _render_call(call)
    else:
        yield from _render_expr(base)
        yield '('
        args = ', '.join(''.join(_render_expr(arg)) for arg in c.args)
        yield args
        yield ')'


def _render_scope(e: ScopeExpr) -> Iterable[str]:
    "Render a scope resolution"
    if e.left == Ident('Decimal128'):
        # Probably looking up a constant?
        attr = e.name
        assert isinstance(attr, Ident)
        const = {
            'kLargestPositive': 'MC_DEC128_LARGEST_POSITIVE',
            'kLargestNegative': 'MC_DEC128_LARGEST_NEGATIVE',
        }[attr.spell]
        yield const
    else:
        assert False, f'Unimplemented scope-resolution expression: {e=}'


def _render_expr(e: Expression) -> Iterable[str]:
    if isinstance(e, (String, Number, Ident)):
        yield e.spell
    elif isinstance(e, CallExpr):
        yield from _render_call(e)
    elif isinstance(e, PrefixExpr) and e.operator == '-':
        yield '-'
        yield from _render_expr(e.operand)
    elif isinstance(e, ScopeExpr):
        yield from _render_scope(e)
    else:
        assert False, f'Do not know how to render expression: {e=}'


def is_boost_none(e: Expression) -> bool:
    return str(e) == 'boost::none'


def _render_opt_wrap(e: Expression) -> Iterable[str]:
    if is_boost_none(e):
        yield '{ .set = false }'
        return
    yield '{ .set = true, .value = '
    yield from _render_expr(e)
    yield ' }'


def _render_edge(e: EdgeInfo) -> Iterable[str]:
    yield '{\n  .value = '
    yield from _render_expr(e.value)
    if not is_boost_none(e.min):
        yield ',\n  .min = '
        yield from _render_opt_wrap(e.min)
    if not is_boost_none(e.max):
        yield ',\n  .max = '
        yield from _render_opt_wrap(e.max)
    if not is_boost_none(e.precision):
        yield ',\n  .precision = '
        yield from _render_opt_wrap(e.precision)
    yield ',\n  .sparsity = '
    yield from _render_expr(e.sparsity)

    # Render the edge list
    yield ',\n  .expectEdges = {'
    elist = e.edges
    assert isinstance(elist, InitList)
    fin = elist.elems[-1]
    leaf = elist.elems[-2]
    prefix = elist.elems[:-2]
    reordered = itertools.chain((fin, leaf), prefix)

    for edge in reordered:
        yield '\n    '
        yield from _render_expr(edge)
        yield ','
    yield '\n  }'
    yield '\n},'


def render_edge(edge: EdgeInfo) -> str:
    return ''.join(_render_edge(edge))


def parse(code: str) -> Sequence[EdgeInfo]:
    # toks = list(tokenize(code))
    toks = LazyList(tokenize(code))
    edges: list[EdgeInfo] = []
    print('// This code is GENERATED! Do not edit!')
    print('// clang-format off')
    for edge in parse_edges(toks):
        s = render_edge(edge)
        print(s)
    return edges


def main():
    code = sys.stdin.read()
    parse(code)


if __name__ == '__main__':
    main()
