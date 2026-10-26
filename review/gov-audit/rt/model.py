"""Third, independent implementation of the agreed U1 gov_action contract,
written from conway.cddl (cardano-ledger b21c518e) on top of rtcbor's
encoding-preserving tree. Scope: transactions whose body holds only key 20
(proposal_procedures) plus optional fee/ttl keys, with an empty witness set.

Contract (as agreed): typed gov_action positions count (mention semantics);
closed kind/arity table; unknown kind, wrong arity or unexpected tag ->
INCOMPLETE; treasury reward-account keys (header stripped, 28-byte hash),
committee removal set AND add-map keys, policy/guardrail hash of kinds 0/2/5;
sets tag-258 or untagged, definite or indefinite, any other tag INCOMPLETE.
`strict_len` additionally treats a reward account of length != 29 as a
malformed typed position (the ledger rejects it); the implementations do not.
"""
from rtcbor import loads

ARITY = {0: 4, 1: 3, 2: 3, 3: 2, 4: 5, 5: 3, 6: 1}
SCOPE_BODY_KEYS = {2, 3, 20}


class Gap(Exception):
    pass


def _bytes(node):
    if node[0] != "b":
        raise Gap(f"expected bytes, got {node[0]}")
    return node[1]


def _hash28(node):
    raw = _bytes(node)
    if len(raw) != 28:
        raise Gap(f"hash of {len(raw)} bytes")
    return raw


def _nil_or_hash28(node, found):
    if node == ("s", "null"):
        return
    found.add(_hash28(node))


def _set_items(node):
    if node[0] == "tag":
        if node[1] != 258:
            raise Gap(f"set under tag {node[1]}")
        node = node[2]
    if node[0] != "a":
        raise Gap("set is not an array")
    return node[1]


def _map_pairs(node):
    if node[0] != "m":
        raise Gap("expected map")
    return node[1]


def _credential(node, found):
    if node[0] != "a" or len(node[1]) != 2:
        raise Gap("credential shape")
    tag, h = node[1]
    if tag[0] != "u" or tag[1] not in (0, 1):
        raise Gap("credential kind")
    found.add(_hash28(h))


def _reward_account(node, found, strict_len):
    raw = _bytes(node)
    if strict_len and len(raw) != 29:
        raise Gap(f"reward account of {len(raw)} bytes")
    if len(raw) >= 29:
        found.add(raw[1:29])


def gov_action(node, found, strict_len=False):
    """Collect every typed position that decodes; raise Gap for the first
    malformation only after collecting what precedes it (positions are visited
    in wire order, and a removal-set/add-map member that is malformed does not
    stop collection of its siblings -- the most permissive reading)."""
    if node[0] != "a" or not node[1]:
        raise Gap("gov_action not a non-empty array")
    items = node[1]
    if items[0][0] != "u" or items[0][1] not in ARITY:
        raise Gap(f"unknown kind {items[0]}")
    kind = items[0][1]
    if len(items) != ARITY[kind]:
        raise Gap(f"kind {kind} arity {len(items)}")
    gaps = []
    if kind == 0:
        _nil_or_hash28(items[3], found)
    elif kind == 2:
        for k, _v in _map_pairs(items[1]):
            try:
                _reward_account(k, found, strict_len)
            except Gap as g:
                gaps.append(str(g))
        _nil_or_hash28(items[2], found)
    elif kind == 4:
        for m in _set_items(items[2]):
            try:
                _credential(m, found)
            except Gap as g:
                gaps.append(str(g))
        for k, _v in _map_pairs(items[3]):
            try:
                _credential(k, found)
            except Gap as g:
                gaps.append(str(g))
    elif kind == 5:
        c = items[2]
        if c[0] != "a" or len(c[1]) != 2:
            raise Gap("constitution shape")
        _nil_or_hash28(c[1][1], found)
    if gaps:
        raise Gap("; ".join(gaps))


def evaluate(tx_bytes, target, strict_len=False, two_element_ok=True):
    found, notes = set(), []
    complete = True
    tx = loads(tx_bytes)
    if tx[0] != "a" or len(tx[1]) != 4:
        return {"found": False, "complete": False, "verdict": "INCOMPLETE", "notes": ["envelope"]}
    body, wits = tx[1][0], tx[1][1]
    if body[0] != "m" or wits != ("m", [], True) and not (wits[0] == "m" and not wits[1]):
        return {"scope": False}
    for k, v in body[1]:
        if k[0] != "u" or k[1] not in SCOPE_BODY_KEYS:
            return {"scope": False}
        if k[1] != 20:
            continue
        try:
            props = _set_items(v)
        except Gap as g:
            complete = False
            notes.append(f"proposals: {g}")
            continue
        for p in props:
            if p[0] != "a" or len(p[1]) < 2 or (len(p[1]) != 4 and not two_element_ok):
                complete = False
                notes.append("proposal shape")
                continue
            try:
                _reward_account(p[1][1], found, strict_len)
            except Gap as g:
                complete = False
                notes.append(f"deposit account: {g}")
            if len(p[1]) >= 3:
                try:
                    gov_action(p[1][2], found, strict_len)
                except Gap as g:
                    complete = False
                    notes.append(f"gov_action: {g}")
    hit = target in found
    verdict = "USE_FOUND" if hit else ("NO_USE" if complete else "INCOMPLETE")
    return {"scope": True, "found": hit, "complete": complete, "verdict": verdict, "notes": notes}
