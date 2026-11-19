"""BM25 over the small fictional policy/FAQ document set, plus the search guard.

Documents are short, so each document is one retrieval unit and a hit returns
the whole page. That is deliberate for the demo: a page with a prompt injection
in it reaches the model in full, so the injection actually gets tested.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

from .paths import DOCS_DIR

MAX_QUERY_CHARS = 200
MAX_TOP_K = 5
K1, B = 1.5, 0.75
STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i in is it of on or our "
    "the this to what when which who why will with you your".split()
)
WORD = re.compile(r"[a-z0-9]+")
DOC_NAME = re.compile(r"[a-z0-9-]{1,60}\.md")
TRAVERSAL = re.compile(r"\.\.|[/\\~%:\x00]")
QUERY_PATH = re.compile(r"\.\.[/\\]|%2e%2e|%2f", re.IGNORECASE)
HIDDEN_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u061c\u180e\u200b-\u200f"
    "\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]"
)
# Heuristic flag for text in a retrieved page that reads like instructions to
# the model. Flagging only: the page is passed through unchanged, and the
# guards on later tool calls are what actually stop anything.
INJECTION_HINTS = re.compile(
    r"ignore (all )?(previous|prior|above) instructions|system notice|note for the ai|"
    r"\b(drop|delete|truncate|alter)\s+(table|from)\b|\bupdate\s+\w+\s+set\b",
    re.IGNORECASE,
)


def tokens(text: str) -> list[str]:
    return [w for w in WORD.findall(text.lower()) if w not in STOPWORDS]


@dataclass
class Doc:
    name: str
    title: str
    text: str


def load_docs(docs_dir: Path = DOCS_DIR) -> list[Doc]:
    docs = []
    for p in sorted(docs_dir.glob("*.md")):
        text = p.read_text(encoding="utf-8").strip()
        title = text.splitlines()[0].lstrip("# ").strip()
        docs.append(Doc(p.name, title, text))
    return docs


class BM25:
    def __init__(self, docs: list[Doc]):
        self.docs = docs
        self.toks = [tokens(d.title + " " + d.title + " " + d.text) for d in docs]
        self.avgdl = sum(len(t) for t in self.toks) / max(len(self.toks), 1)
        df: dict[str, int] = {}
        for t in self.toks:
            for w in set(t):
                df[w] = df.get(w, 0) + 1
        n = len(docs)
        self.idf = {w: math.log(1 + (n - c + 0.5) / (c + 0.5)) for w, c in df.items()}

    def search(self, query: str, top_k: int = 3, doc: str | None = None) -> list[dict]:
        q = tokens(query)
        scored = []
        for d, t in zip(self.docs, self.toks):
            if doc is not None and d.name != doc:
                continue
            s = 0.0
            for w in q:
                f = t.count(w)
                if f:
                    s += self.idf[w] * f * (K1 + 1) / (f + K1 * (1 - B + B * len(t) / self.avgdl))
            if s > 0 or doc is not None:
                scored.append((round(s, 4), d))
        scored.sort(key=lambda x: (-x[0], x[1].name))
        return [{"doc": d.name, "title": d.title, "score": s, "text": d.text} for s, d in scored[:top_k]]


@dataclass
class SearchVerdict:
    allowed: bool
    rule: str
    detail: str
    doc: str | None = None


def check_search(query: str, doc: str | None, known_docs: set[str]) -> SearchVerdict:
    for field_name, value in (("query", query), ("doc", doc)):
        if value is None:
            continue
        m = HIDDEN_CHARS.search(value)
        if m:
            return SearchVerdict(False, "search.hidden_chars", f"{field_name} contains invisible or control character U+{ord(m.group(0)):04X}")
    if len(query) > MAX_QUERY_CHARS:
        return SearchVerdict(False, "search.query_too_long", f"query is {len(query)} characters, limit is {MAX_QUERY_CHARS}")
    if not WORD.search(query.lower()):
        return SearchVerdict(False, "search.empty_query", "query has no searchable words")
    if QUERY_PATH.search(query):
        return SearchVerdict(False, "search.path_traversal", "query looks like a file path; search takes words, not paths")
    if doc is not None:
        if TRAVERSAL.search(doc):
            return SearchVerdict(False, "search.path_traversal", f"doc {doc!r} contains path characters; give a bare document name like returns-policy.md")
        name = doc if doc.endswith(".md") else doc + ".md"
        if not DOC_NAME.fullmatch(name):
            return SearchVerdict(False, "search.bad_doc_name", f"doc {doc!r} is not a valid document name")
        if name not in known_docs:
            return SearchVerdict(False, "search.unknown_doc", f"no document named {name!r}")
        doc = name
    return SearchVerdict(True, "search.ok", "query accepted", doc=doc)


def injection_flags(text: str) -> list[str]:
    return sorted({m.group(0).lower() for m in INJECTION_HINTS.finditer(text)})
