import pytest

from guardagent.search import BM25, check_search, injection_flags, load_docs


@pytest.fixture(scope="module")
def docs():
    return load_docs()


@pytest.fixture(scope="module")
def names(docs):
    return {d.name for d in docs}


def test_bm25_ranking(docs):
    idx = BM25(docs)
    assert idx.search("return window for opened items")[0]["doc"] == "returns-policy.md"
    assert idx.search("support hours saturday")[0]["doc"] == "support-hours.md"
    assert idx.search("silver tier discount")[0]["doc"] == "loyalty-tiers.md"
    assert idx.search("zzzz qqqq") == []
    only = idx.search("discount", doc="shipping.md")
    assert [h["doc"] for h in only] == ["shipping.md"]


def test_allowed(names):
    v = check_search("free shipping threshold", None, names)
    assert v.allowed
    v = check_search("fees", "shipping", names)
    assert v.allowed and v.doc == "shipping.md"


SEARCH_BLOCKED = [
    ("root", "../../../etc/passwd", "search.path_traversal"),
    ("root", "..\\..\\windows\\win.ini", "search.path_traversal"),
    ("root", "/etc/passwd", "search.path_traversal"),
    ("root", "%2e%2e%2fetc", "search.path_traversal"),
    ("root", "~/.ssh/id_rsa", "search.path_traversal"),
    ("root", "file:shipping.md", "search.path_traversal"),
    ("root", "shipping.md\x00.txt", "search.hidden_chars"),
    ("../../etc/passwd", None, "search.path_traversal"),
    ("%2E%2E%2Fsecrets", None, "search.path_traversal"),
    ("root", "Shipping.MD", "search.bad_doc_name"),
    ("root", "shipping .md", "search.bad_doc_name"),
    ("root", "secrets.md", "search.unknown_doc"),
    ("???", None, "search.empty_query"),
    ("refund​ policy", None, "search.hidden_chars"),
    ("x" * 201, None, "search.query_too_long"),
]


@pytest.mark.parametrize("query,doc,rule", SEARCH_BLOCKED)
def test_blocked(names, query, doc, rule):
    v = check_search(query, doc, names)
    assert not v.allowed
    assert v.rule == rule


def test_injection_flagged(docs):
    by = {d.name: d for d in docs}
    assert injection_flags(by["partner-integration-notes.md"].text)
    assert injection_flags(by["bulk-discount-faq.md"].text)
    assert injection_flags(by["shipping.md"].text) == []
