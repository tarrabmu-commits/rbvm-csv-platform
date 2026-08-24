#!/usr/bin/env python3
from __future__ import annotations

from decimal import Decimal
import importlib.util
import inspect
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/rank-rbvm-mvp-priority.py"
SOURCE = SCRIPT.read_text(encoding="utf-8")
EXPECTED_SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"

for token in (
    "pareto_relations",
    "dominance_relation",
    "row-weighted dominance counts",
    "O(n) retained memory",
):
    if token not in SOURCE:
        raise AssertionError(f"optimized Pareto implementation missing {token}")

spec = importlib.util.spec_from_file_location("rbvm_mvp_priority", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
if module.METHOD_SHA256 != EXPECTED_SHA:
    raise AssertionError("optimization changed the frozen MVP method identity")

implementation = inspect.getsource(module.pareto_relations)
if "outgoing =" in implementation or "outgoing[" in implementation:
    raise AssertionError("Pareto implementation must not retain a quadratic outgoing adjacency graph")


def reference(vectors):
    remaining = set(vectors)
    fronts = {}
    front_number = 1
    while remaining:
        front = []
        for candidate in sorted(remaining):
            if not any(
                other != candidate and module.dominates(vectors[other], vectors[candidate])
                for other in remaining
            ):
                front.append(candidate)
        if not front:
            raise RuntimeError("reference Pareto calculation made no progress")
        for index in front:
            fronts[index] = front_number
        remaining.difference_update(front)
        front_number += 1

    dominates_count = {index: 0 for index in vectors}
    dominated_by_count = {index: 0 for index in vectors}
    for left, left_vector in vectors.items():
        for right, right_vector in vectors.items():
            if left == right:
                continue
            if module.dominates(left_vector, right_vector):
                dominates_count[left] += 1
                dominated_by_count[right] += 1
    return fronts, dominates_count, dominated_by_count


rng = random.Random(20260824)
value_sets = [
    [Decimal(0), Decimal(1)],
    [Decimal(0), Decimal(1)],
    [Decimal(1), Decimal(2), Decimal(3), Decimal(4)],
    [Decimal("0.01"), Decimal("0.1"), Decimal("0.5"), Decimal("0.9")],
    [Decimal("3.0"), Decimal("5.0"), Decimal("7.0"), Decimal("9.0")],
]
for trial in range(30):
    row_count = rng.randint(1, 90)
    vectors = {}
    pool = []
    for _ in range(max(4, row_count // 3)):
        pool.append(tuple(rng.choice(values) for values in value_sets))
    for index in range(row_count):
        vectors[index] = rng.choice(pool)
    expected = reference(vectors)
    actual = module.pareto_relations(vectors)
    if actual != expected:
        raise AssertionError(f"optimized Pareto result differs from reference on trial {trial}")

strong = (Decimal(1), Decimal(1), Decimal(4), Decimal("0.9"), Decimal("9.0"))
weak = (Decimal(0), Decimal(0), Decimal(1), Decimal("0.1"), Decimal("3.0"))
vectors = {0: strong, 1: strong, 2: weak, 3: weak, 4: weak}
fronts, dominates_count, dominated_by_count = module.pareto_relations(vectors)
if [fronts[index] for index in range(5)] != [1, 1, 2, 2, 2]:
    raise AssertionError("identical-vector front semantics drift")
if [dominates_count[index] for index in (0, 1)] != [3, 3]:
    raise AssertionError("row-weighted dominates counts drift for grouped vectors")
if [dominated_by_count[index] for index in (2, 3, 4)] != [2, 2, 2]:
    raise AssertionError("row-weighted dominated-by counts drift for grouped vectors")

print("RBVM MVP Pareto optimization equivalence + linear retained memory guard: PASS")
