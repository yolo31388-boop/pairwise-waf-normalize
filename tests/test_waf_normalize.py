import pytest

from security.waf_normalize import (
    parse_query,
    decode_repeated,
    normalize_unicode,
    normalize_path,
    reassemble_chunks
)


def test_query_dup():
    assert parse_query('a=1&a=2') == {'a': ['1', '2']}

def test_query_empty():
    assert parse_query('') == {}

def test_query_plus():
    assert parse_query('a=hello+world') == {'a': ['hello world']}

def test_decode_once():
    assert decode_repeated('%2e%2e') == '..'

def test_decode_double():
    assert decode_repeated('%252e%252e') == '..'

def test_decode_stable():
    assert decode_repeated('abc') == 'abc'

def test_unicode_nfkc():
    assert normalize_unicode('ＡＢＣ') == 'ABC'

def test_unicode_fullwidth():
    assert normalize_unicode('／') == '/'

def test_path_backslash():
    assert normalize_path('a\\b') == 'a/b'

def test_path_dot():
    assert normalize_path('a/../b') == 'b'

def test_path_double():
    assert normalize_path('a//b') == 'a/b'

def test_chunks_join():
    assert reassemble_chunks(['ab', 'cd']) == 'abcd'

def test_chunks_empty():
    assert reassemble_chunks([]) == ''

def test_chunks_boundary():
    assert reassemble_chunks(['se', 'lect']) == 'select'

def test_query_pollution():
    assert parse_query('a=1&a=2')['a'] == ['1', '2']
