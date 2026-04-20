import base64
import itertools
import os
import time
from dataclasses import dataclass
from typing import Dict, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY = b"1234567890abcdef"

DEFAULT_BINARY_TO_DNA_MAP = {
    "00": "A",
    "01": "C",
    "10": "G",
    "11": "T",
}

ALTERNATE_MAPPINGS = [
    DEFAULT_BINARY_TO_DNA_MAP,
    {"00": "T", "01": "G", "10": "C", "11": "A"},
    {"00": "C", "01": "A", "10": "T", "11": "G"},
    {"00": "G", "01": "T", "10": "A", "11": "C"},
]

ALL_BINARY_TO_DNA_MAPPINGS = [
    {
        "00": permutation[0],
        "01": permutation[1],
        "10": permutation[2],
        "11": permutation[3],
    }
    for permutation in itertools.permutations(["A", "C", "G", "T"])  # 4! = 24 mappings
]


@dataclass
class CandidateResult:
    candidate_name: str
    mapping: Dict[str, str]
    score: float
    gc_ratio: float
    max_homopolymer_run: int
    elapsed_ms: float
    binary_bits: int
    dna_length: int
    stage_trace: List[dict]
    encrypted_bytes: bytes
    decrypted_bytes: bytes


def _aes_encrypt(plaintext: bytes, key: bytes = AES_KEY) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def _aes_decrypt(encrypted_bytes: bytes, key: bytes = AES_KEY) -> bytes:
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext


def _bytes_to_binary(data: bytes) -> str:
    return "".join(format(byte, "08b") for byte in data)


def _binary_to_dna(binary: str, binary_to_dna_map: Dict[str, str]) -> str:
    return "".join(binary_to_dna_map[binary[index:index + 2]] for index in range(0, len(binary), 2))


def _dna_to_rna(dna: str) -> str:
    return dna.replace("T", "U")


def _rna_to_dna(rna: str) -> str:
    return rna.replace("U", "T")


def _dna_to_binary(dna: str, dna_to_binary_map: Dict[str, str]) -> str:
    return "".join(dna_to_binary_map[nucleotide] for nucleotide in dna)


def _binary_to_bytes(binary: str) -> bytes:
    as_bytes = bytearray()
    for index in range(0, len(binary), 8):
        as_bytes.append(int(binary[index:index + 8], 2))
    return bytes(as_bytes)


def _gc_ratio(dna: str) -> float:
    if not dna:
        return 0.0
    gc_count = sum(1 for char in dna if char in ("G", "C"))
    return gc_count / len(dna)


def _max_homopolymer_run(dna: str) -> int:
    if not dna:
        return 0
    longest = 1
    current = 1
    for index in range(1, len(dna)):
        if dna[index] == dna[index - 1]:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def _candidate_score(gc_ratio: float, max_run: int, elapsed_ms: float, fidelity_ok: bool) -> float:
    fidelity_component = 1.0 if fidelity_ok else 0.0
    gc_balance_component = max(0.0, 1.0 - abs(gc_ratio - 0.5) * 2.0)
    run_component = 1.0 / max(1, max_run)
    speed_component = 1.0 / max(1.0, elapsed_ms)
    return (
        0.6 * fidelity_component
        + 0.2 * gc_balance_component
        + 0.15 * run_component
        + 0.05 * speed_component
    )


def mapping_signature(mapping: Dict[str, str]) -> str:
    return "".join(mapping[key] for key in ("00", "01", "10", "11"))


def evaluate_candidate_bytes(
    payload_bytes: bytes,
    mapping: Dict[str, str],
    candidate_name: str,
    payload_type: str = "text",
) -> CandidateResult:
    started = time.perf_counter()
    dna_to_binary_map = {value: key for key, value in mapping.items()}

    encrypted_bytes = _aes_encrypt(payload_bytes)
    binary_text = _bytes_to_binary(encrypted_bytes)
    dna_text = _binary_to_dna(binary_text, mapping)
    rna_text = _dna_to_rna(dna_text)

    reverse_dna = _rna_to_dna(rna_text)
    reverse_binary = _dna_to_binary(reverse_dna, dna_to_binary_map)
    reconstructed_encrypted = _binary_to_bytes(reverse_binary)
    decrypted = _aes_decrypt(reconstructed_encrypted)

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    gc_ratio = _gc_ratio(dna_text)
    max_run = _max_homopolymer_run(dna_text)
    fidelity_ok = decrypted == payload_bytes
    score = _candidate_score(gc_ratio=gc_ratio, max_run=max_run, elapsed_ms=elapsed_ms, fidelity_ok=fidelity_ok)

    stage_trace = [
        {
            "stage": "Payload Input",
            "output": f"{len(payload_bytes)} bytes",
            "method": f"{payload_type} payload",
        },
        {"stage": "AES-CBC Encrypt", "output": f"{len(encrypted_bytes)} bytes", "method": "PKCS7 + AES-128"},
        {"stage": "Bytes -> Binary", "output": f"{len(binary_text)} bits", "method": "8-bit encoding"},
        {
            "stage": "Binary -> DNA",
            "output": f"{len(dna_text)} bases",
            "method": f"{candidate_name} ({mapping_signature(mapping)})",
        },
        {"stage": "DNA -> RNA", "output": f"{len(rna_text)} bases", "method": "T->U transcription"},
        {"stage": "RNA -> DNA", "output": f"{len(reverse_dna)} bases", "method": "U->T reverse transcription"},
        {
            "stage": "DNA -> Binary",
            "output": f"{len(reverse_binary)} bits",
            "method": f"{candidate_name} ({mapping_signature(mapping)})",
        },
        {"stage": "AES-CBC Decrypt", "output": f"{len(decrypted)} bytes", "method": "PKCS7 + AES-128"},
    ]

    return CandidateResult(
        candidate_name=candidate_name,
        mapping=mapping,
        score=score,
        gc_ratio=gc_ratio,
        max_homopolymer_run=max_run,
        elapsed_ms=elapsed_ms,
        binary_bits=len(binary_text),
        dna_length=len(dna_text),
        stage_trace=stage_trace,
        encrypted_bytes=encrypted_bytes,
        decrypted_bytes=decrypted,
    )


def evaluate_candidate(message: str, mapping: Dict[str, str], candidate_name: str) -> CandidateResult:
    return evaluate_candidate_bytes(
        payload_bytes=message.encode("utf-8"),
        mapping=mapping,
        candidate_name=candidate_name,
        payload_type="text",
    )


def encode_cipher_preview(cipher_bytes: bytes, max_chars: int = 56) -> str:
    encoded = base64.b64encode(cipher_bytes).decode("ascii")
    if len(encoded) <= max_chars:
        return encoded
    return f"{encoded[:max_chars]}..."


def run_candidate_set(message: str, mappings: List[Dict[str, str]] | None = None) -> List[CandidateResult]:
    selected = mappings or ALTERNATE_MAPPINGS
    results: List[CandidateResult] = []
    for index, mapping in enumerate(selected):
        name = f"Method-{index + 1}"
        results.append(evaluate_candidate(message=message, mapping=mapping, candidate_name=name))
    return results
