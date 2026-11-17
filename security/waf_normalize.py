"""WAF request normalization primitives.

A WAF must inspect requests the same way the backend will interpret them.
Each helper here closes one normalization gap that otherwise lets an
attacker smuggle payloads past the rules:

* ``parse_query`` / ``parse_body`` / ``parse_multipart`` -- take parameters
  from *every* parser the backend actually uses and keep the full value set
  for duplicate names (HTTP parameter pollution).
* ``decode_repeated`` -- percent-decode in a loop until the string is
  stable, so double (or N-fold) encoding cannot hide traversal sequences.
* ``normalize_unicode`` -- NFKC before inspection, collapsing full-width
  and compatibility characters to their canonical form.
* ``normalize_path`` -- cross-platform path normalization: backslashes are
  separators (Windows backends), dot segments are resolved, duplicate
  separators collapsed.
* ``reassemble_chunks`` -- rebuild chunked transfer-encoding bodies so a
  keyword split across a chunk boundary is visible again.
"""

import unicodedata
from urllib.parse import unquote, unquote_plus

# Safety valve against pathological inputs (e.g. "%25" repeated thousands of
# times): decoding always shrinks such strings, so real traffic stabilizes
# long before this bound. It exists only to guarantee termination.
_MAX_DECODE_ROUNDS = 64


def _as_text(value):
    """Return ``value`` as text, decoding bytes as UTF-8 (latin-1 fallback)."""
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('latin-1')
    return str(value)


def parse_query(query):
    """Parse a URL query string into ``{name: [all values]}``.

    Every occurrence of a duplicated name is preserved in order instead of
    silently keeping the first (or last) one: the rule engine must see the
    whole parameter set because backends disagree about which duplicate
    wins. ``+`` means space and percent-encoding is resolved, matching the
    standard ``application/x-www-form-urlencoded`` parser.
    """
    text = _as_text(query)
    params = {}
    if not text:
        return params

    for pair in text.split('&'):
        if not pair:
            continue
        name, sep, value = pair.partition('=')
        # partition gives value='' both for "a=" and for a bare "a"; both
        # legitimately carry an empty value.
        name = unquote_plus(name)
        value = unquote_plus(value) if sep else ''
        params.setdefault(name, []).append(value)
    return params


def decode_repeated(value):
    """Percent-decode ``value`` repeatedly until the result stops changing.

    One pass leaves ``%252e%252e`` as ``%2e%2e``; looping to a fixed point
    fully resolves double/N-fold encoding so the normalized form is what
    the backend ultimately works with. Inputs without encoding are returned
    untouched, and malformed escapes are left as literal text (``unquote``
    does not raise on them).
    """
    text = _as_text(value)
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(text)
        if decoded == text:
            return decoded
        text = decoded
    return text


def normalize_unicode(value):
    """Apply NFKC normalization before rule inspection.

    NFKC folds full-width forms (``ＡＢＣ`` -> ``ABC``, ``／`` -> ``/``) and
    compatibility characters onto their canonical equivalents, removing the
    homoglyph layer used to bypass literal signatures.
    """
    return unicodedata.normalize('NFKC', _as_text(value))


def normalize_path(path):
    """Normalize a request path for cross-platform backends.

    Backslashes are treated as separators (a Windows backend resolves
    ``a\\b`` and ``a/b`` to the same resource), repeated separators are
    collapsed, and ``.`` / ``..`` dot segments are resolved lexically so
    traversal sequences cannot survive normalization. Leading slashes and
    trailing slashes are preserved.
    """
    text = _as_text(path).replace('\\', '/')

    absolute = text.startswith('/')
    segments = []
    for segment in text.split('/'):
        if segment == '' or segment == '.':
            continue
        if segment == '..':
            if segments and segments[-1] != '..':
                segments.pop()
            elif not absolute:
                # Relative path with nothing to consume: keep the traversal
                # visible rather than silently dropping it.
                segments.append('..')
            continue
        segments.append(segment)

    result = '/'.join(segments)
    if absolute:
        result = '/' + result
    if text.endswith('/') and not result.endswith('/'):
        result += '/'
    return result


def reassemble_chunks(body):
    """Reassemble a chunked request body.

    Accepts either an already-split sequence of chunk payloads (the common
    in-memory case) or the raw ``Transfer-Encoding: chunked`` wire format:

        <hex size>\\r\\n<payload>\\r\\n ... 0\\r\\n[trailers]\\r\\n\\r\\n

    Returns the concatenated payload, so signatures cannot hide in the
    chunk boundaries.
    """
    if isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            text = raw.decode('latin-1')
        return _reassemble_wire(text, want_bytes=True)

    text = _as_text(body)
    if not isinstance(body, (list, tuple)) and _looks_like_chunked(text):
        return _reassemble_wire(text, want_bytes=False)

    # Pre-split payloads: join in order.
    if isinstance(body, (list, tuple)):
        return ''.join(_as_text(chunk) for chunk in body)
    return text


def _looks_like_chunked(text):
    first_line = text.split('\r\n', 1)[0]
    try:
        int(first_line.split(';', 1)[0].strip(), 16)
    except ValueError:
        return False
    return '\r\n' in text


def _reassemble_wire(text, want_bytes):
    parts = []
    pos = 0
    total = len(text)
    while pos < total:
        line_end = text.find('\r\n', pos)
        if line_end == -1:
            # Truncated framing: do not pretend it is valid, return what we
            # have decoded so far.
            break
        size_field = text[pos:line_end].split(';', 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            # Not actually chunked (or a trailer section we cannot parse);
            # hand the original back untouched.
            return text.encode('latin-1') if want_bytes else text
        pos = line_end + 2
        if size == 0:
            # Last chunk; any remaining bytes are trailers/terminator.
            break
        parts.append(text[pos:pos + size])
        pos += size
        if text[pos:pos + 2] == '\r\n':
            pos += 2

    joined = ''.join(parts)
    return joined.encode('latin-1') if want_bytes else joined


def parse_multipart(body, boundary):
    """Extract fields from a ``multipart/form-data`` body.

    The body is split on its actual boundary and every named part is
    included -- multipart parameters were previously never inspected at
    all. File parts are reported under their form field name with the
    filename attached.
    """
    text = _as_text(body)
    if isinstance(boundary, bytes):
        boundary = boundary.decode('latin-1')
    delimiter = '--' + boundary

    params = {}
    for part in text.split(delimiter):
        # Skip preamble, closing delimiter and empty pieces.
        if not part or part in ('--', '--\r\n', '--\n'):
            continue
        part = part.lstrip('\r\n')
        if part.startswith('--'):
            break
        header_blank = part.find('\r\n\r\n')
        if header_blank == -1:
            header_blank = part.find('\n\n')
            if header_blank == -1:
                continue
            header_block = part[:header_blank]
            content = part[header_blank + 2:]
        else:
            header_block = part[:header_blank]
            content = part[header_blank + 4:]
        # Part payloads are CRLF-terminated before the next boundary.
        if content.endswith('\r\n'):
            content = content[:-2]
        elif content.endswith('\n'):
            content = content[:-1]

        name = None
        filename = None
        for header in header_block.split('\r\n'):
            if ':' not in header:
                continue
            key, _, value = header.partition(':')
            if key.strip().lower() != 'content-disposition':
                continue
            for token in value.split(';'):
                token = token.strip()
                if token.startswith('name='):
                    name = token[5:].strip('"')
                elif token.startswith('filename='):
                    filename = token[9:].strip('"')
        if name is None:
            continue
        if filename is not None:
            params.setdefault(name, []).append(
                {'filename': filename, 'content': content}
            )
        else:
            params.setdefault(name, []).append(content)
    return params


def parse_body(body, content_type):
    """Pick the parser that matches the request's actual ``Content-Type``.

    Returns ``{name: [all values]}`` regardless of encoding, covering
    urlencoded forms, multipart forms (boundary fields included) and JSON
    objects (scalar leaves only; nested structures keep their JSON shape).
    Unknown content types yield an empty mapping rather than being parsed
    with the wrong grammar.
    """
    text = _as_text(body)
    media_type = (content_type or '').split(';', 1)[0].strip().lower()

    if media_type in ('application/x-www-form-urlencoded', ''):
        return parse_query(text)

    if media_type == 'multipart/form-data':
        boundary = None
        for directive in (content_type or '').split(';')[1:]:
            directive = directive.strip()
            if directive.lower().startswith('boundary='):
                boundary = directive[len('boundary='):].strip('"')
                break
        if boundary is None:
            raise ValueError('multipart/form-data request missing boundary')
        return parse_multipart(text, boundary)

    if media_type == 'application/json':
        import json
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {key: [value] for key, value in data.items()}

    return {}
