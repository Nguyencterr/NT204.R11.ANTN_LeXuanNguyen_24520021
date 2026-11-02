"""Small state machine for splitting a Snort subset rule safely.

Only three jobs are done here:

* split the header from the parenthesized option block,
* split the option block on ``;`` delimiters that are *outside* quotes,
* extract quoted values without letting ``;``, ``:``, ``,``, ``(`` or ``)``
  inside a quoted string terminate the option.

The tokenizer is intentionally not a general Snort parser. It raises
:class:`RuleSyntaxError` for malformed text and
:class:`RuleUnsupportedError` for syntax we recognise but do not implement.
"""

from __future__ import annotations


class RuleSyntaxError(ValueError):
    """The rule text is malformed and cannot be parsed."""


class RuleUnsupportedError(ValueError):
    """The rule is well-formed but uses syntax outside the supported subset."""


#: Escapes accepted inside a quoted ``content`` / ``msg`` value.
_SIMPLE_ESCAPES = {
    "\\": "\\",
    '"': '"',
    ";": ";",
    ":": ":",
    ",": ",",
    "(": "(",
    ")": ")",
}


def _scan_quotes(
    text: str,
    start: int = 0,
    stop_at_open_paren: bool = False,
) -> tuple[int | None, bool]:
    """
    Scan ``text`` and report the first unquoted ``(`` plus quote balance.

    Returns ``(open_paren_index, in_quote_at_end)``.
    """

    in_quote = False
    escaped = False

    for index in range(start, len(text)):

        char = text[index]

        if escaped:

            escaped = False
            continue

        if in_quote and char == "\\":

            escaped = True
            continue

        if char == '"':

            in_quote = not in_quote
            continue

        if not in_quote and stop_at_open_paren and char == "(":

            return index, in_quote

    return None, in_quote


def split_header_and_options(text: str) -> tuple[str, str]:
    """
    Split ``alert tcp ... ( ... )`` into ``(header, options)``.

    The option block must be the last non-whitespace content of the rule, and
    quotes must balance. Parentheses inside quoted values are preserved.
    """

    if not isinstance(text, str) or not text.strip():

        raise RuleSyntaxError("rule text is empty")

    text = text.strip()

    open_index, _ = _scan_quotes(text, stop_at_open_paren=True)

    # A quote that never closes before the first '(' is caught below; if a
    # quote opens inside the header and contains the '(', there is no valid
    # options block at all.
    if open_index is None:

        raise RuleSyntaxError("missing '(' opening the rule option block")

    header = text[:open_index].strip()

    if not header:

        raise RuleSyntaxError("rule header is empty")

    # Find the matching ')' while ignoring quoted parentheses.
    depth = 0
    in_quote = False
    escaped = False
    close_index: int | None = None

    for index in range(open_index, len(text)):

        char = text[index]

        if escaped:

            escaped = False
            continue

        if in_quote and char == "\\":

            escaped = True
            continue

        if char == '"':

            in_quote = not in_quote
            continue

        if in_quote:

            continue

        if char == "(":

            depth += 1

        elif char == ")":

            depth -= 1

            if depth == 0:

                close_index = index
                break

    if in_quote:

        raise RuleSyntaxError("unclosed quoted string in rule")

    if close_index is None:

        raise RuleSyntaxError("missing ')' closing the rule option block")

    trailing = text[close_index + 1:].strip()

    if trailing:

        raise RuleSyntaxError(
            "unexpected text after the closing ')' of the option block"
        )

    options = text[open_index + 1:close_index]

    return header, options


def split_option_tokens(options: str) -> list[str]:
    """
    Split an option block on unquoted ``;`` separators.

    A single trailing ``;`` (the normal Snort form) is accepted. Any other
    empty token, such as ``;;`` or a leading ``;``, is a syntax error.
    """

    tokens: list[str] = []
    start = 0
    in_quote = False
    escaped = False

    for index, char in enumerate(options):

        if escaped:

            escaped = False
            continue

        if in_quote and char == "\\":

            escaped = True
            continue

        if char == '"':

            in_quote = not in_quote
            continue

        if char == ";" and not in_quote:

            tokens.append(options[start:index].strip())
            start = index + 1

    if in_quote:

        raise RuleSyntaxError("unclosed quoted string in rule options")

    tail = options[start:].strip()

    if tail:

        tokens.append(tail)

    # The last token is naturally empty when the rule ends with ';'.
    while tokens and not tokens[-1]:

        tokens.pop()

    if any(not token for token in tokens):

        raise RuleSyntaxError("empty option token between ';' delimiters")

    return tokens


def split_option_token(token: str) -> tuple[str, str | None]:
    """
    Split ``key:value`` on the first unquoted colon.

    ``nocase`` has no value, so the returned value is ``None``.
    """

    in_quote = False
    escaped = False

    for index, char in enumerate(token):

        if escaped:

            escaped = False
            continue

        if in_quote and char == "\\":

            escaped = True
            continue

        if char == '"':

            in_quote = not in_quote
            continue

        if char == ":" and not in_quote:

            return token[:index].strip(), token[index + 1:].strip()

    return token.strip(), None


def _quoted_inner(value: str, option: str) -> str:
    """Validate and return the raw inner text of a quoted value."""

    text = value.strip()

    if not text.startswith('"'):

        raise RuleSyntaxError(f"{option} value must be a double-quoted string")

    if len(text) < 2 or not text.endswith('"'):

        raise RuleSyntaxError(f"{option} value has an unclosed quote")

    inner = text[1:-1]

    in_quote = False
    escaped = False

    for char in inner:

        if escaped:

            escaped = False
            continue

        if char == "\\":

            escaped = True
            continue

        if char == '"':

            raise RuleSyntaxError(
                f"{option} value contains an unescaped double quote"
            )

    if escaped:

        raise RuleSyntaxError(f"{option} value ends with a dangling escape")

    return inner


def decode_quoted_string(value: str, *, option: str = "value") -> str:
    """Decode a quoted ``msg``/``classtype``-style string."""

    inner = _quoted_inner(value, option)
    return _decode_escapes(inner, option=option, allow_unknown=True)


def decode_quoted_content(value: str) -> str:
    """
    Decode a quoted ``content`` value.

    Binary/hex syntax (``|...|``) and the ``\\xNN`` escape form are outside the
    supported subset and are reported as unsupported, never guessed at.
    """

    inner = _quoted_inner(value, "content")

    if "|" in inner:

        raise RuleUnsupportedError(
            "hex/binary content syntax (|...|) is not supported"
        )

    return _decode_escapes(inner, option="content", allow_unknown=False)


def _decode_escapes(
    text: str,
    *,
    option: str,
    allow_unknown: bool,
) -> str:

    result: list[str] = []
    index = 0

    while index < len(text):

        char = text[index]

        if char != "\\":

            result.append(char)
            index += 1
            continue

        if index + 1 >= len(text):

            raise RuleSyntaxError(f"{option} value ends with a dangling escape")

        escaped = text[index + 1]

        if escaped in _SIMPLE_ESCAPES:

            result.append(_SIMPLE_ESCAPES[escaped])
            index += 2
            continue

        if escaped in ("x", "u", "U", "N"):

            raise RuleUnsupportedError(
                f"escape sequence '\\{escaped}' in {option} is not supported"
            )

        if allow_unknown:

            # For human-readable metadata keep the text as written.
            result.append("\\")
            result.append(escaped)
            index += 2
            continue

        raise RuleUnsupportedError(
            f"escape sequence '\\{escaped}' in {option} is not supported"
        )

    return "".join(result)


def unquote_if_needed(value: str) -> str:
    """Return a plain token, accepting an optional surrounding quote pair."""

    text = value.strip()

    if text.startswith('"'):

        return decode_quoted_string(text)

    return text


__all__ = [
    "RuleSyntaxError",
    "RuleUnsupportedError",
    "decode_quoted_content",
    "decode_quoted_string",
    "split_header_and_options",
    "split_option_token",
    "split_option_tokens",
    "unquote_if_needed",
]
