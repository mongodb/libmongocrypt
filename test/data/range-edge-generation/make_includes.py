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
    def is_id(self) -> bool:
        """Is this an identifier?"""
        return IDENT_RE.match(self.spell) is not None

    @property
    def is_num(self) -> bool:
        """Is this a number?"""
        return NUM_RE.match(self.spell) is not None

    @property
    def is_str(self) -> bool:
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
    Yield every item X in 'items'. Between each X, yield each item in `by`.
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
    """
    Consumes a given string, keeping track of line and column position information.
    """

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
        """
        Discard n characters from the input
        """
        skipped = self.string[:n]
        self._line += skipped.count('\n')
        nlpos = skipped.rfind('\n')
        if nlpos >= 0:
            self._col = len(skipped) - nlpos
        self._off += n

    def skipws(self):
        """
        Consume all whitespace at the beginning of the current input
        """
        ws = WHITESPACE_RE.match(self.string)
        if not ws:
            return
        self.consume(len(ws[0]))


def tokenize(sc: Scanner) -> Iterable[Token]:
    "Extract the tokens from the given code"
    # Discard leading space, of course:
    sc.skipws()
    while sc.string:
        # If we have a comment, just skip it:
        comment = LINE_COMMENT_RE.match(sc.string)
        if comment:
            sc.consume(len(comment[0]))
            continue

        # Try to match basic primary tokens. A "real" C++ tokenizer needs to be
        # context-sensitive, but we only implement "just enough" to be useful.
        mat = (
            STRING_RE.match(sc.string)  #
            or IDENT_RE.match(sc.string)  #
            or NUM_RE.match(sc.string))
        if mat:
            # A basic token: Strings, identifiers, and number literals.
            tok = mat[0]
            yield Token(tok, sc.line)
            sc.consume(len(tok))
        elif sc.string.startswith('::'):
            # Scope resolution operator
            yield Token(sc.string[:2], sc.line)
            sc.consume(2)
        elif sc.string[0] in ',&{}[]().-<>+':
            # Basic one-character punctuators. We don't handle any digraphs.
            yield Token(sc.string[0], sc.line)
            sc.consume(1)
        else:
            # Unknown. Generate an error:
            snippet = sc.string[:min(len(sc.string), 30)]
            raise RuntimeError(f'Unknown token at {cquote(snippet)} '
                               f'(Line {sc.line}, column {sc.col})"')
        sc.skipws()


class LazyList(Generic[T]):
    """
    Create a forward-only list that lazily advances an iterable as items are
    requested, and drops items as they are discarded.
    """

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
"A token-generating lazy list"


def parse_ilist(toks: Tokenizer) -> InitList:
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
            # Just skip the comma. This may or may not be followed by another element.
            toks.adv()
    return InitList(acc)


def parse_call_args(toks: Tokenizer,
                    open: str = '(',
                    close: str = ')') -> Sequence[Expression]:
    """
    Parse the argument list of a function/template call. The tokenizer must be
    positioned at the opening token
    """
    lpar = toks.at(0)
    assert lpar and lpar.spell == open, f'Expected opening "{open}" (Got {lpar=})'
    toks.adv()
    acc: list[Expression] = []

    peek = toks.at(0)
    while peek and peek.spell != close:
        # Parse an argument:
        x = parse_expr(toks)
        acc.append(x)
        # We expect either a comma or a closing token next:
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
    # Discard the closing token:
    toks.adv()
    return acc


def parse_nameid(toks: Tokenizer) -> Ident | TmplIdent:
    """
    Parse a name-id. This may be a bare identifier, or an identifier followed by
    template arguments. We don't handle less-than expressions correctly, but this
    dosen't matter for our current inputs. A more sofisticated system may be
    required later on.
    """
    idn = toks.at(0)
    assert idn and idn.is_id, f'Expected identifier beginning a nameid (Got {idn=}'
    toks.adv()
    angle = toks.at(0)
    if not angle or angle.spell != '<':
        # A regular identifier
        return Ident(idn.spell)
    # An identifier with template arguments:
    # (Or, an itentifier followed by a less-than symbol. We don't handle that
    # case, and don't currently need to.)
    targs = parse_call_args(toks, '<', '>')
    return TmplIdent(idn.spell, targs)


def parse_expr(toks: Tokenizer) -> Expression:
    "Parse an arbitrary expression"
    return parse_infix(toks)


def parse_infix(toks: Tokenizer) -> Expression:
    "Parse a binary infix-expression"
    x = parse_prefix_expr(toks)
    peek = toks.at(0)
    while peek:
        s = peek.spell
        if s not in '+-':
            break
        # Binary "+" or "-" (We don't care about other operators (yet))
        toks.adv()
        rhs = parse_prefix_expr(toks)
        x = InfixExpr(x, s, rhs)
        peek = toks.at(0)
    return x


def parse_prefix_expr(toks: Tokenizer) -> Expression:
    "Parse a unary prefix expression (currently, only '&' and '-' are handled)"
    peek = toks.at(0)
    if peek and peek.spell in '-&':
        toks.adv()
        x = parse_prefix_expr(toks)
        return PrefixExpr(peek.spell, x)
    return parse_suffixexpr(toks)


def parse_suffixexpr(toks: Tokenizer) -> Expression:
    "Parse a suffix-expression. (For now, that only includes call expressions.)"
    x = parse_primary_expr(toks)
    peek = toks.at(0)
    # Look ahead for scope resolution or function call (could also handle
    # dot '.' and subscript, but we don't care (yet))
    while peek:
        if peek.spell == '::':
            # Scope resolution:
            toks.adv()
            name = parse_nameid(toks)
            x = ScopeExpr(x, name)
        elif peek.spell == '(':
            # Function call:
            args = parse_call_args(toks)
            x = CallExpr(x, args)
        else:
            break
        peek = toks.at(0)
    return x


def parse_primary_expr(toks: Tokenizer) -> Expression:
    x: Expression
    peek = toks.at(0)
    assert peek, f'Unexpected EOF when expected an expression'
    if peek.spell == '{':
        x = parse_ilist(toks)
    elif peek.is_str:
        x = String(peek.spell)
        toks.adv()
    elif peek.is_id:
        x = parse_nameid(toks)
    elif peek.is_num:
        x = Number(peek.spell)
        toks.adv()
    else:
        raise RuntimeError(f'Unknown expression beginning with token "{peek}"')
    return x


def parse_edges(toks: Tokenizer) -> Iterable[EdgeInfo]:
    "Parse the edges from the given sequence of C++ tokens"
    while toks.at(0):
        ilist = parse_expr(toks)
        assert isinstance(
            ilist, InitList
        ), f'Expected init-list for an edge element (Got {ilist!r})'
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
        assert peek and peek.spell == ',', f'Expect a comma following edge element (Got {peek=})'
        toks.adv()


def parse_mincovers(toks: Tokenizer) -> Iterable[MinCoverInfo]:
    while toks.at(0):
        ilist = parse_expr(toks)
        assert isinstance(
            ilist, InitList
        ), f'Expected init-list for a mincover element (Got {ilist!r})'
        lb, ub, mn, mx, sparsity = ilist.elems[:5]
        has_precision = len(ilist.elems) == 7
        prec = ilist.elems[5] if has_precision else BOOST_NONE
        expect = ilist.elems[-1]
        yield MinCoverInfo(lb, ub, mn, mx, sparsity, prec, expect)
        peek = toks.at(0)
        assert peek and peek.spell == ',', f'Expected comma following edge element (Got {peek=})'
        toks.adv()


def _render_limit(typ: Expression, limit: Ident) -> Iterable[str]:
    """
    Render a value from std::numeric_limits<>. We only use a few of them so far.
    """
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
    return _render_expr(e)


def _render_call(c: CallExpr) -> Iterable[str]:
    """
    Render a function call expression. This may render as some other arbitrary
    expression since we need to handle C++-isms.
    """
    # Intercept calls to numeric_limits:
    if (isinstance(c.fn, ScopeExpr)  #
            and c.args == []  #
            and isinstance(c.fn.left, ScopeExpr)  #
            and str(c.fn.left.left) == 'std'  #
            and isinstance(c.fn.left.name, TmplIdent)  #
            and c.fn.left.name.name == 'numeric_limits'):
        # We're looking for numeric limits
        assert isinstance(c.fn.name, Ident), f'Unimplemented limit: {c=}'
        return _render_limit(c.fn.left.name.targs[0], c.fn.name)

    if str(c.fn) == 'std::string':
        # We're constructing a std::string. All our inputs just use inline literals, so just render
        # those.
        assert len(c.args) == 1, c
        assert isinstance(c.args[0], String), c
        return _render_string(c.args[0])

    # Intercept calls to "Decimal128"
    if c.fn == Ident('Decimal128'):
        assert len(c.args) == 1, f'Too many args for Decimal128? {c=}'
        arg = c.args[0]
        if isinstance(arg, Number) and '.' not in arg.spell:
            # We can convert from an integer driectly
            return _render_call(CallExpr(Ident('MC_DEC128'), [arg]))
        if isinstance(arg, String):
            # They're passing a string to Decimal128(), so we do the same
            return _render_call(CallExpr(Ident('mc_dec128_from_string'),
                                         [arg]))
        # Other argument:
        assert isinstance(
            arg, (Number,
                  PrefixExpr)), f'Unimplemented argument to Decimal128: {arg=}'
        # Wrap the argument in a string, since a double literal may lose precision and generate an incorrect value:
        call = CallExpr(Ident('mc_dec128_from_string'),
                        [String(cquote(str(arg)))])
        return _render_call(call)
    # Otherwise: Render anything else as just a function call:
    fn = _render_expr(c.fn)
    each_arg = map(_render_expr, c.args)
    comma_args = join_with(each_arg, ', ')
    args = chain.from_iterable(comma_args)
    return chain(fn, '(', args, ')')


def _render_scope(e: ScopeExpr) -> Iterable[str]:
    """
    Render a scope resolution expression. This only cares about constants of
    Decimal128 yet.
    """
    if e.left == Ident('Decimal128') and isinstance(e.name, Ident):
        # Looking up a constant on Decimal128, presumably
        attr = e.name
        const = {
            'kLargestPositive': 'MC_DEC128_LARGEST_POSITIVE',
            'kLargestNegative': 'MC_DEC128_LARGEST_NEGATIVE',
        }[attr.spell]
        return [const]
    assert False, f'Unimplemented scope-resolution expression: {e=}'


def _render_infix(e: InfixExpr) -> Iterable[str]:
    if isinstance(e.rhs, String) and e.oper == '+':
        # We're building a string with operator+. We don't have a special
        # "string concat" to use, so just do preprocessor string splicing
        # (for now). This also assumes that the operands are also string literals or other string
        # concatenations, but that's all we need for now.
        return chain(_render_expr(e.lhs), _render_expr(e.rhs))
    # We don't implement any other infix expressions yet.
    assert False, f'Unimplemented infix expression: {e=}'


def _render_string(s: String) -> Iterable[str]:
    """
    Render a string literal.
    """
    if not s.spell.startswith('R'):
        # Just a regular string. We are safe to emit this
        return [s.spell]
    # C doesn't support the R"()" 'raw string' (yet). We'll un-prettify it:
    mat = STRING_RE.match(s.spell)
    assert mat, s
    c = mat.group('raw_content')
    lines = c.splitlines()
    with_nl = (f'{l}\n' for l in lines)
    quoted = map(cquote, with_nl)
    return join_with(quoted, '\n    ')


def _render_expr(e: Expression) -> Iterable[str]:
    """
    Generate a rendering of an arbitrary expression
    """
    if isinstance(e, (Number, Ident)):
        return [e.spell]
    elif isinstance(e, String):
        return _render_string(e)
    elif isinstance(e, CallExpr):
        return _render_call(e)
    elif isinstance(e, PrefixExpr):
        return chain(e.operator, _render_expr(e.operand))
    elif isinstance(e, ScopeExpr):
        return _render_scope(e)
    elif isinstance(e, InfixExpr):
        return _render_infix(e)
    else:
        assert False, f'Do not know how to render expression: {e=}'


def _render_opt_wrap(e: Expression) -> Iterable[str]:
    """
    Render a value that is wrapped as an optional. If boost::none, emits a
    braced-init "{.set = false}", otherwise "{.set=true, .value = render(e) }"
    """
    if e == BOOST_NONE:
        return '{ .set = false }'
    return chain('{ .set = true, .value = ', _render_expr(e), ' }')


def designit(attr: str, x: Iterable[str]) -> Iterable[str]:
    """
    Render a 2-space indented designated initializer, with a trailing comma
    and newline
    """
    return chain(f'  .{attr} = ', x, ',\n')


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

    return chain(
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
    return chain(
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
             render: Callable[[T], Iterable[str]]):
    """
    Generate code.

    :param code: The input code to parse.
    :param parser: A parsing function that accepts a tokenizer and emits objects of type T.
    :param render: A renderer that accepts instances of T and returns an iterable of strings.

    For every object V yielded by parse(tokens), every string
    yielded from render(V) will be written to stdout.
    """
    scan = Scanner(code)
    toks = LazyList(tokenize(scan))
    print('// This code is GENERATED! Do not edit!')
    print('// clang-format off')
    items = parser(toks)
    each_rendered = map(render, items)
    strings = chain.from_iterable(each_rendered)
    for s in strings:
        sys.stdout.write(s)


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
