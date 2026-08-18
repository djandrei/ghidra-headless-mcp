"""Indexing and searching decompiled pseudo-C.

Two search modes over the same cached corpus:

* literal  — a regex over the C text, reporting the matching lines.
* semantic — ranked by TF-IDF cosine similarity, so "validate licence key"
  finds a function that never contains those words but is built from related
  identifiers.

pyghidra-mcp backs its semantic mode with ChromaDB embeddings. This uses TF-IDF
instead, deliberately: ChromaDB pulls in onnxruntime and roughly half a gigabyte
of dependencies, which is a heavy price for a server whose selling point is that
it needs nothing but Ghidra. The query interface is the same and the index is
on-disk either way, so an embedding backend can replace the ranker later without
changing a tool signature.

Everything here is a pure function over lists and dicts, so it is tested
directly rather than through a subprocess.
"""

import math
import re
from collections import Counter

# Tokens that carry no signal in decompiler output: C keywords, Ghidra's
# synthesised type and variable prefixes, and the noise of every function.
STOPWORDS = frozenset(
    """
    if else for while do switch case break continue return goto sizeof typedef
    struct union enum static const volatile extern register signed unsigned
    int char short long float double void bool auto inline restrict
    undefined undefined1 undefined2 undefined4 undefined8 code byte word dword qword
    uint ulong ushort uchar bool_ null true false
    var local param in stack halt_baddata
    """.split()
)

# Negative lookbehind so a hex literal does not leak in as an identifier:
# without it, 0xdeadbeef tokenises to the meaningless term "xdeadbeef".
# Magic constants are the business of literal search, not this ranker.
_TOKEN = re.compile(r"(?<![0-9A-Za-z_])[A-Za-z_][A-Za-z0-9_]*")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokenize(text: str) -> list[str]:
    """Split C text into lowercase identifier tokens.

    snake_case and camelCase are both split, so `decrypt_config` and
    `decryptConfig` produce the same terms and a query matches either.
    Ghidra's synthesised names (uVar1, local_10) reduce to stopwords and drop
    out, which stops every function looking alike.
    """
    tokens: list[str] = []
    for raw in _TOKEN.findall(text):
        for part in _CAMEL.sub(" ", raw).replace("_", " ").split():
            part = part.lower()
            # A bare number-suffixed fragment like "var1" carries no meaning.
            part = part.rstrip("0123456789") or part
            if len(part) < 3 or part in STOPWORDS:
                continue
            tokens.append(part)
    return tokens


def build_index(documents: list[dict]) -> dict:
    """Build a TF-IDF index over [{name, address, c}, ...].

    Returns a plain dict so it can be written straight to JSON and reloaded
    without a library.
    """
    postings: list[dict] = []
    df: Counter = Counter()

    for doc in documents:
        counts = Counter(tokenize(doc.get("c", "")))
        if counts:
            df.update(counts.keys())
        postings.append(
            {"name": doc.get("name", ""), "address": doc.get("address", ""),
             "counts": dict(counts)}
        )

    total = len(postings)
    entries = []
    for post in postings:
        vector = {}
        for term, count in post["counts"].items():
            tf = 1.0 + math.log(count)
            idf = math.log(total / (1 + df[term])) + 1.0
            vector[term] = tf * idf
        norm = math.sqrt(sum(w * w for w in vector.values())) or 1.0
        entries.append(
            {
                "name": post["name"],
                "address": post["address"],
                "vector": {t: w / norm for t, w in vector.items()},
            }
        )

    return {"document_count": total, "df": dict(df), "entries": entries}


def _query_vector(index: dict, query: str) -> dict:
    total = max(index.get("document_count", 0), 1)
    df = index.get("df", {})
    counts = Counter(tokenize(query))
    vector = {}
    for term, count in counts.items():
        tf = 1.0 + math.log(count)
        idf = math.log(total / (1 + df.get(term, 0))) + 1.0
        vector[term] = tf * idf
    norm = math.sqrt(sum(w * w for w in vector.values())) or 1.0
    return {t: w / norm for t, w in vector.items()}


def semantic_search(index: dict, query: str, limit: int = 5) -> list[dict]:
    """Rank indexed functions against a query by cosine similarity.

    Both vectors are L2-normalised at build time, so the dot product is the
    cosine. Zero-similarity documents are dropped rather than padded out to
    `limit` — a result list padded with unrelated functions is worse than a
    short one.
    """
    qvec = _query_vector(index, query)
    if not qvec:
        return []

    scored = []
    for entry in index.get("entries", []):
        vector = entry["vector"]
        # Iterate the shorter side; a query has a handful of terms and a
        # function has hundreds.
        score = sum(weight * vector.get(term, 0.0) for term, weight in qvec.items())
        if score > 0:
            scored.append(
                {"function": entry["name"], "address": entry["address"],
                 "score": round(score, 6)}
            )

    scored.sort(key=lambda hit: (-hit["score"], hit["function"]))
    return scored[: max(0, limit)]


def literal_search(
    documents: list[dict], pattern: str, limit: int = 5, context: int = 0
) -> list[dict]:
    """Regex search over decompiled C, reporting the first match per function.

    Case-insensitive, matching the other search tools. Raises re.error for an
    invalid pattern so the caller can report it as a bad argument.
    """
    compiled = re.compile(pattern, re.IGNORECASE)
    hits: list[dict] = []

    for doc in documents:
        lines = doc.get("c", "").splitlines()
        matched = [(n, line) for n, line in enumerate(lines, 1) if compiled.search(line)]
        if not matched:
            continue
        first_line, text = matched[0]
        start = max(0, first_line - 1 - context)
        end = min(len(lines), first_line + context)
        hits.append(
            {
                "function": doc.get("name", ""),
                "address": doc.get("address", ""),
                "line_number": first_line,
                "line": text.strip(),
                "match_count": len(matched),
                "snippet": "\n".join(lines[start:end]) if context else None,
            }
        )
        if len(hits) >= limit > 0:
            break

    return hits
