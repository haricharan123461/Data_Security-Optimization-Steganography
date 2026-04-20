import itertools
import math
import random
from dataclasses import dataclass
from typing import Dict, List, Tuple

from dna_crypto import ALL_BINARY_TO_DNA_MAPPINGS, CandidateResult, evaluate_candidate_bytes, mapping_signature

EXHAUSTIVE_METHOD_NAME = "Exhaustive DNA Permutation Search"
COMET_METHOD_NAME = "COMET (Characteristic Objects Method)"
HILL_CLIMBING_METHOD_NAME = "Hill-Climbing Local Search"


@dataclass
class CometOptimizationResult:
    best_result: CandidateResult
    all_results: List[CandidateResult]
    searched_mappings: List[Dict[str, str]]
    exhaustive_method_count: int
    comet_generation_count: int
    optimization_methods: List[str]
    compliance_trace: List[Dict[str, str]]


def _tfn_membership(value: float, a: float, m: float, b: float) -> float:
    if math.isclose(a, m) and math.isclose(m, b):
        return 1.0
    if math.isclose(a, m):
        if value <= m:
            return 1.0
        if value >= b:
            return 0.0
        denominator = max(1e-9, b - m)
        return (b - value) / denominator
    if math.isclose(m, b):
        if value >= m:
            return 1.0
        if value <= a:
            return 0.0
        denominator = max(1e-9, m - a)
        return (value - a) / denominator
    if value <= a or value >= b:
        return 0.0
    if value == m:
        return 1.0
    if value < m:
        denominator = max(1e-9, m - a)
        return (value - a) / denominator
    denominator = max(1e-9, b - m)
    return (b - value) / denominator


def _criterion_value_tuple(candidate: CandidateResult) -> Tuple[float, float, float, float]:
    fidelity = 1.0 if candidate.decrypted_bytes else 0.0
    gc_balance = max(0.0, 1.0 - abs(candidate.gc_ratio - 0.5) * 2.0)
    run_quality = 1.0 / max(1, candidate.max_homopolymer_run)
    speed_quality = 1.0 / max(1.0, candidate.elapsed_ms)
    return fidelity, gc_balance, run_quality, speed_quality


def _build_tfn_levels(values: List[float]) -> Dict[str, Tuple[float, float, float]]:
    minimum = min(values)
    maximum = max(values)
    mid = (minimum + maximum) / 2.0
    if math.isclose(minimum, maximum):
        epsilon = 1e-6
        minimum -= epsilon
        maximum += epsilon
        mid = (minimum + maximum) / 2.0
    return {
        "low": (minimum, minimum, mid),
        "medium": (minimum, mid, maximum),
        "high": (mid, maximum, maximum),
    }


def _pairwise_preference(alpha_left: float, alpha_right: float) -> float:
    if alpha_left < alpha_right:
        return 0.0
    if math.isclose(alpha_left, alpha_right):
        return 0.5
    return 1.0


def _comet_preference_scores(candidates: List[CandidateResult]) -> Tuple[List[float], Dict[str, object]]:
    criterion_vectors = [_criterion_value_tuple(candidate) for candidate in candidates]
    transposed = list(zip(*criterion_vectors))

    fuzzy_sets = [_build_tfn_levels(list(axis_values)) for axis_values in transposed]
    labels = ["low", "medium", "high"]

    characteristic_objects = list(itertools.product(labels, repeat=4))
    core_lookup = {"low": 0.0, "medium": 0.5, "high": 1.0}

    criterion_weights = [0.45, 0.25, 0.20, 0.10]
    expert_scores = []
    for characteristic_object in characteristic_objects:
        expert_score = 0.0
        for criterion_index, level in enumerate(characteristic_object):
            expert_score += criterion_weights[criterion_index] * core_lookup[level]
        expert_scores.append(expert_score)

    mej = []
    for left_score in expert_scores:
        row = []
        for right_score in expert_scores:
            row.append(_pairwise_preference(left_score, right_score))
        mej.append(row)

    sj = [sum(row) for row in mej]
    sj_min = min(sj)
    sj_max = max(sj)
    if math.isclose(sj_max, sj_min):
        preference_vector = [1.0 for _ in sj]
    else:
        preference_vector = [(value - sj_min) / (sj_max - sj_min) for value in sj]

    candidate_preferences: List[float] = []
    for criterion_value in criterion_vectors:
        activations = []
        for rule_index, characteristic_object in enumerate(characteristic_objects):
            rule_memberships = []
            for criterion_index, level in enumerate(characteristic_object):
                a, m, b = fuzzy_sets[criterion_index][level]
                membership = _tfn_membership(criterion_value[criterion_index], a, m, b)
                rule_memberships.append(membership)
            activation = min(rule_memberships)
            activations.append((activation, preference_vector[rule_index]))

        denominator = sum(weight for weight, _ in activations)
        if denominator <= 1e-12:
            candidate_preferences.append(0.0)
        else:
            numerator = sum(weight * preference for weight, preference in activations)
            candidate_preferences.append(numerator / denominator)

    comet_artifacts = {
        "criteria": ["fidelity", "gc_balance", "homopolymer_quality", "speed_quality"],
        "characteristic_object_count": len(characteristic_objects),
        "equations": ["Eq.16", "Eq.17", "Eq.18", "Eq.19", "Eq.20", "Eq.21", "Eq.22", "Eq.23"],
        "fuzzy_set_levels": [
            {
                "criterion": "fidelity",
                "levels": fuzzy_sets[0],
            },
            {
                "criterion": "gc_balance",
                "levels": fuzzy_sets[1],
            },
            {
                "criterion": "homopolymer_quality",
                "levels": fuzzy_sets[2],
            },
            {
                "criterion": "speed_quality",
                "levels": fuzzy_sets[3],
            },
        ],
    }
    return candidate_preferences, comet_artifacts


def _mutate_mapping(mapping: Dict[str, str]) -> Dict[str, str]:
    keys = ["00", "01", "10", "11"]
    values = [mapping[key] for key in keys]
    first, second = random.sample(range(4), 2)
    values[first], values[second] = values[second], values[first]
    return {key: value for key, value in zip(keys, values)}


def _dedupe_mappings(mappings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    unique: List[Dict[str, str]] = []
    for mapping in mappings:
        signature = tuple(mapping[key] for key in ("00", "01", "10", "11"))
        if signature not in seen:
            unique.append(mapping)
            seen.add(signature)
    return unique


def optimize_with_comet(
    message: str | None = None,
    payload_bytes: bytes | None = None,
    payload_type: str = "text",
    iterations: int = 2,
    comet_count: int = 8,
) -> CometOptimizationResult:
    if payload_bytes is None:
        if message is None:
            raise ValueError("Either 'message' or 'payload_bytes' must be provided.")
        payload_bytes = message.encode("utf-8")
        payload_type = "text"

    exhaustive_results = [
        evaluate_candidate_bytes(
            payload_bytes=payload_bytes,
            mapping=mapping,
            candidate_name=f"DNA-Perm-{index + 1:02d}-{mapping_signature(mapping)}",
            payload_type=payload_type,
        )
        for index, mapping in enumerate(ALL_BINARY_TO_DNA_MAPPINGS)
    ]
    comet_preferences, comet_artifacts = _comet_preference_scores(exhaustive_results)
    for candidate, preference in zip(exhaustive_results, comet_preferences):
        candidate.score = preference
    exhaustive_results.sort(key=lambda result: result.score, reverse=True)

    best_candidate = exhaustive_results[0]
    hill_climbing_steps = 0
    current_mapping = best_candidate.mapping

    for _ in range(max(0, iterations)):
        hill_climbing_steps += 1
        neighbors = [_mutate_mapping(current_mapping) for _ in range(max(2, comet_count))]
        neighbor_candidates = [
            evaluate_candidate_bytes(
                payload_bytes=payload_bytes,
                mapping=neighbor,
                candidate_name=f"HC-{hill_climbing_steps}-{index + 1}-{mapping_signature(neighbor)}",
                payload_type=payload_type,
            )
            for index, neighbor in enumerate(neighbors)
        ]

        merged = exhaustive_results + neighbor_candidates
        merged_preferences, _ = _comet_preference_scores(merged)
        for candidate, preference in zip(merged, merged_preferences):
            candidate.score = preference
        merged.sort(key=lambda result: result.score, reverse=True)

        best_neighbor = merged[0]
        if best_neighbor.score > best_candidate.score:
            best_candidate = best_neighbor
            current_mapping = best_neighbor.mapping
            exhaustive_results = merged
        else:
            break

    all_results: List[CandidateResult] = list(exhaustive_results)
    all_results.sort(key=lambda result: result.score, reverse=True)
    best_result = all_results[0]

    compliance_trace = [
        {
            "equation": "Eq.16",
            "description": "Criteria and fuzzy-number sets defined for COMET dimensions.",
        },
        {
            "equation": "Eq.17-Eq.19",
            "description": "Characteristic objects generated via Cartesian product of criterion cores.",
        },
        {
            "equation": "Eq.20-Eq.22",
            "description": "MEJ pairwise preference matrix and summed judgments converted to preference vector P.",
        },
        {
            "equation": "Eq.23",
            "description": "Fuzzy IF-AND-THEN rule base used with Mamdani-style inference for alternative preference.",
        },
        {
            "equation": "HC Steps 1-4",
            "description": "Hill-climbing local search performed in neighborhood of best mapping candidate.",
        },
    ]

    return CometOptimizationResult(
        best_result=best_result,
        all_results=all_results,
        searched_mappings=_dedupe_mappings([candidate.mapping for candidate in all_results]),
        exhaustive_method_count=len(ALL_BINARY_TO_DNA_MAPPINGS),
        comet_generation_count=hill_climbing_steps,
        optimization_methods=[EXHAUSTIVE_METHOD_NAME, COMET_METHOD_NAME, HILL_CLIMBING_METHOD_NAME],
        compliance_trace=compliance_trace + [
            {
                "equation": "COMET Artifacts",
                "description": f"Characteristic objects={comet_artifacts['characteristic_object_count']}; criteria={', '.join(comet_artifacts['criteria'])}",
            }
        ],
    )
