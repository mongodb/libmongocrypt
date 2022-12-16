"""
Script to convert the MongoDB server test vector #include files into their
C-equivalent counterpart
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from itertools import chain
from typing import (Callable, Generic, Iterable, NamedTuple, Sequence, TypeVar,
                    Union, cast)

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


class InfixExpr(NamedTuple):
    "An infix expression"
    lhs: Expression
    oper: str
    rhs: Expression

    def __str__(self) -> str:
        return f'{self.lhs} {self.oper} {self.rhs}'


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
                   InfixExpr, TmplIdent, Ident]
"An arbitrary expression (from a small subset of C++)"

BOOST_NONE = ScopeExpr(Ident('boost'), Ident('none'))


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


class MinCoverInfo(NamedTuple):
    "Information about a mincover generation"
    lb: Expression
    "Lower bound for the operation, if provided"
    ub: Expression
    "Upper bound for the operation, if provided"
    min: Expression
    "Minimum value"
    max: Expression
    "Maximum value"
    sparsity: Expression
    "Sparsity of the mincover"
    precision: Expression
    "Optional: Precision of the range"
    expect_string: Expression
    "The expected result string"


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
NUM_RE = re.compile(
    r'''^
    # The unfortunate many ways to write a number
    # First: Floats:
    (
        ( \d+\.\d+  # Both whole and fractional part
        | \.\d+     # ".NNNN" (No whole part)
        | \d+\.     # "NNNN." (no fractional part)
        )
        # Optional: "f" suffix
        f?
    # Integers:
    )|(
        (
            0x              # Hex prefix
            [0-9a-fA-F']+   # Hex digits (with digit separator)

        |   0       # Octal prefix
            [0-7']*  # May have no digits. "0" is an octal literal oof.

        |   0b      # Binary prefix
            [01']   # Bits

        |   [1-9]   # Decimal integer
            [0-9']*
        )
        # There could be a type modifying suffix:
        [uU]?       # Unsigned
        [lL]{0,2}   # Long, or VERY long
    )
''', re.VERBOSE)
"Matches a base10 numeric literal"
STRING_RE = re.compile(
    r'''
    # Regular strings:
    "(\\.|[^"])*"
  | # Raw strings:
    R
    "
    (?P<delim>.*?)  # The delimiter
    \(
       (?P<raw_content>(.|\s)*?)
    \)
    (?P=delim)  # Stop when we find the delimiter again
    "
''', re.VERBOSE)
"Matches a string literal"
LINE_COMMENT_RE = re.compile(r'^//.*?\n\s*')
WHITESPACE_RE = re.compile(r'[ \n\t\r\f]+')


def cquote(s: str) -> str:
    "Enquote a string to be used as a C string literal"
    # Coincidentally, JSON strings are valid C strings
    return json.dumps(s)


def join_with(items: Iterable[T], by: Iterable[T]) -> Iterable[T]:
    """
    Yield ever item X in 'items'. Between each X, yield each item in `by`.
    """
    STOP = object()
    # Iterate each item, and yield the sentinel STOP when we finish.
    # This is far easier than dancing around StopIteration.
    ch = chain(items, [STOP])
    it = iter(ch)
    item = next(it)
    while item is not STOP:
        yield cast(T, item)
        item = next(it)
        if item is not STOP:
            # Clone the iterable so we can re-iterate it again later:
            by, tee = itertools.tee(by, 2)
            yield from tee


class Scanner:

    def __init__(self, s: str) -> None:
        self._str = s
        self._off = 0
        self._line = 1
        self._col = 1

    @property
    def string(self) -> str:
        """Return the current string content"""
        return self._str[self._off:]

    @property
    def line(self):
        """The current line number"""
        return self._line

    @property
    def col(self):
        """The current column number"""
        return self._col

    def consume(self, n: int) -> None:
        skipped = self.string[:n]
        self._line += skipped.count('\n')
        nlpos = skipped.rfind('\n')
        if nlpos >= 0:
            self._col = len(skipped) - nlpos
        self._off += n

    def skipws(self):
        ws = WHITESPACE_RE.match(self.string)
        if not ws:
            return
        self.consume(len(ws[0]))


def tokenize(sc: Scanner) -> Iterable[Token]:
    "Extract the tokens from the given code"
    sc.skipws()
    while sc.string:
        comment = LINE_COMMENT_RE.match(sc.string)
        if comment:
            sc.consume(len(comment[0]))
            continue

        mat = (
            STRING_RE.match(sc.string)  #
            or IDENT_RE.match(sc.string)  #
            or NUM_RE.match(sc.string))
        if mat:
            tok = mat[0]
            yield Token(tok, sc.line)
            sc.consume(len(tok))
        elif sc.string.startswith('::'):
            yield Token(sc.string[:2], sc.line)
            sc.consume(2)
        elif sc.string[0] in ',&{}[]().-<>+':
            yield Token(sc.string[0], sc.line)
            sc.consume(1)
        else:
            snippet = sc.string[:min(len(sc.string), 30)]
            raise RuntimeError(f'Unknown token at {cquote(snippet)} '
                               f'(Line {sc.line}, column {sc.col})"')
        sc.skipws()


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
        ), f'Expected comma or "{close}" following argument (Got "{peek}")'
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
    return parse_infix(toks)


def parse_infix(toks: Tokenizer) -> Expression:
    x = parse_suffixexpr(toks)
    peek = toks.at(0)
    while peek:
        s = peek.spell
        if s in '+-':
            toks.adv()
            rhs = parse_suffixexpr(toks)
            x = InfixExpr(x, s, rhs)
        else:
            break
        peek = toks.at(0)
    return x


def parse_suffixexpr(toks: Tokenizer) -> Expression:
    x = parse_primary_expr(toks)
    peek = toks.at(0)

    while peek and peek.spell == '(':
        args = parse_call_args(toks)
        x = CallExpr(x, args)
        peek = toks.at(0)
    return x


def parse_primary_expr(toks: Tokenizer) -> Expression:
    x: Expression
    peek = toks.at(0)
    assert peek, f'Unexpected EOF when expected an expression'
    if peek.spell == '{':
        x = parse_ilist(toks)
    elif peek.spell in '-&':
        toks.adv()
        oper = parse_suffixexpr(toks)
        x = PrefixExpr(peek.spell, oper)
    elif peek.isstr:
        x = String(peek.spell)
        toks.adv()
    elif peek.isid:
        x = parse_nameid(toks)
    elif peek.isnum:
        x = Number(peek.spell)
        toks.adv()
    else:
        raise RuntimeError(f'Unknown expression beginning with token "{peek}"')
    # Look ahead for suffix expressions
    peek = toks.at(0)
    while peek and peek.spell in ('::', ):
        if peek.spell == '::':
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
            BOOST_NONE,
            edges,
        )
        peek = toks.at(0)
        assert peek and peek.spell == ',', f'Expect a comma following edge element'
        toks.adv()


def parse_mincovers(toks: Tokenizer) -> Iterable[MinCoverInfo]:
    while toks.at(0):
        ilist = parse_expr(toks)
        assert isinstance(ilist, InitList), ilist
        lb, ub, mn, mx, sparsity = ilist.elems[:5]
        has_precision = len(ilist.elems) == 7
        prec = ilist.elems[5] if has_precision else BOOST_NONE
        expect = ilist.elems[-1]
        yield MinCoverInfo(lb, ub, mn, mx, sparsity, prec, expect)
        peek = toks.at(0)
        assert peek and peek.spell == ',', f'Expected comma following edge element (Got {peek=})'
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

    if str(base) == 'std::string':
        # We're constructing a std::string. All our inputs just use inline literals, so just render
        # those.
        assert len(c.args) == 1, c
        yield from _render_expr(c.args[0])
        return

    # Intercept calls to "Decimal128"
    elif base == Ident('Decimal128'):
        assert len(c.args) == 1, f'Too many args for Decimal128? {c.args=}'
        arg = c.args[0]
        if isinstance(arg, Number) and '.' not in arg.spell:
            # We can convert from an integer driectly
            yield from _render_call(CallExpr(Ident('MC_DEC128'), [arg]))
        elif isinstance(arg, String):
            # They're passing a string to Decimal128(), so we do the same
            yield from _render_call(
                CallExpr(Ident('mc_dec128_from_string'), [arg]))
        else:
            assert isinstance(
                arg,
                (Number,
                 PrefixExpr)), f'Unimplemented argument to Decimal128: {arg=}'
            # Wrap the argument in a string, since a double literal may lose precision and generate an incorrect value:
            call = CallExpr(Ident('mc_dec128_from_string'),
                            [String(cquote(str(arg)))])
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


def _render_infix(e: InfixExpr) -> Iterable[str]:
    if isinstance(e.rhs, String) and e.oper == '+':
        # We're building a string. We don't have a special "string concat" to
        # use, so just do preprocessor string splicing (for now)
        yield from _render_expr(e.lhs)
        yield from _render_expr(e.rhs)
    else:
        assert False, f'Unimplemented infix expression: {e=}'


def _render_string(s: String) -> Iterable[str]:
    if not s.spell.startswith('R'):
        # Just a regular string. We are safe to emit this
        yield s.spell
        return
    # C doesn't support the R"()" 'raw string' (yet). We'll un-prettify it:
    mat = STRING_RE.match(s.spell)
    assert mat, s
    c = mat.group('raw_content')
    lines = c.splitlines()
    with_nl = (f'{l}\n' for l in lines)
    quoted = map(cquote, with_nl)
    yield from join_with(quoted, (s for s in '\n    '))


def _render_expr(e: Expression) -> Iterable[str]:
    if isinstance(e, (Number, Ident)):
        yield e.spell
    elif isinstance(e, String):
        yield from _render_string(e)
    elif isinstance(e, CallExpr):
        yield from _render_call(e)
    elif isinstance(e, PrefixExpr) and e.operator == '-':
        yield '-'
        yield from _render_expr(e.operand)
    elif isinstance(e, ScopeExpr):
        yield from _render_scope(e)
    elif isinstance(e, InfixExpr):
        yield from _render_infix(e)
    else:
        assert False, f'Do not know how to render expression: {e=}'


def _render_opt_wrap(e: Expression) -> Iterable[str]:
    if e == BOOST_NONE:
        yield '{ .set = false }'
        return
    yield '{ .set = true, .value = '
    yield from _render_expr(e)
    yield ' }'


def designit(attr: str, x: Iterable[str]) -> Iterable[str]:
    """
    Render a 2-space indented designated initializer, with a trailing comma
    and newline
    """
    yield from chain(f'  .{attr} = ', x, ',\n')


def render_edge(e: EdgeInfo) -> Iterable[str]:
    # Permute the edge list for easier matching
    elist = e.edges
    assert isinstance(elist, InitList)
    fin = elist.elems[-1]
    leaf = elist.elems[-2]
    prefix = elist.elems[:-2]
    reordered = chain((fin, leaf), prefix)
    wrapped = (chain('\n    ', _render_expr(e), ',') for e in reordered)
    braced_edges = chain('{', chain.from_iterable(wrapped), '\n  }')

    yield from chain(
        '{\n',
        designit('value', _render_expr(e.value)),
        designit('min', _render_opt_wrap(e.min)),
        designit('max', _render_opt_wrap(e.max)),
        # The upstream vectors include a 'precision' field, but we don't use it (yet).
        # designit('precision', _render_opt_wrap(e.precision)),
        designit('sparsity', _render_expr(e.sparsity)),
        designit('expectEdges', braced_edges),
        '},\n',
    )


def render_mincover(mc: MinCoverInfo) -> Iterable[str]:
    yield from chain(
        '{\n',
        designit('lowerBound', _render_expr(mc.lb)),
        designit('includeLowerBound', 'true'),
        designit('upperBound', _render_expr(mc.ub)),
        designit('includeUpperBound', 'true'),
        designit('sparsity', _render_expr(mc.sparsity)),
        designit('min', _render_opt_wrap(mc.min)),
        designit('max', _render_opt_wrap(mc.max)),
        designit('precision', _render_opt_wrap(mc.precision)),
        designit('expectMincoverString',
                 chain('\n    ', _render_expr(mc.expect_string))),
        '},\n',
    )


def generate(code: str, parser: Callable[[Tokenizer], Iterable[T]],
             render: Callable[[T], Iterable[str]]) -> Sequence[EdgeInfo]:
    scan = Scanner(code)
    toks = LazyList(tokenize(scan))
    edges: list[EdgeInfo] = []
    print('// This code is GENERATED! Do not edit!')
    print('// clang-format off')
    items = parser(toks)
    each_rendered = map(render, items)
    strings = chain.from_iterable(each_rendered)
    for s in strings:
        sys.stdout.write(s)
    return edges


def main(argv: Sequence[str]):
    parser = argparse.ArgumentParser()
    parser.add_argument('kind',
                        help='What kind of construct are we parsing',
                        choices=['edges', 'mincovers'])
    args = parser.parse_args(argv)
    code = sys.stdin.read()
    if args.kind == 'edges':
        generate(code, parse_edges, render_edge)
    elif args.kind == 'mincovers':
        generate(code, parse_mincovers, render_mincover)
    else:
        assert False


if __name__ == '__main__':
    main(sys.argv[1:])
