import base64
import hashlib
from collections import defaultdict
from datetime import datetime

from flask import Flask, render_template
from flask_socketio import SocketIO, emit, join_room

from comet_optimizer import optimize_with_comet
from dna_crypto import encode_cipher_preview

app = Flask(__name__)
app.config["SECRET_KEY"] = "dna-stego-protocol"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

room_members = defaultdict(set)


def _candidate_optimization_method(candidate_name: str) -> str:
    if candidate_name.startswith("DNA-Perm-"):
        mapping_signature = candidate_name.split("-")[-1]
        return f"DNA Permutation Mapping {mapping_signature} (COMET Eq.16-23)"
    if candidate_name.startswith("HC-"):
        mapping_signature = candidate_name.split("-")[-1]
        return f"Hill-Climbing Neighbor Mapping {mapping_signature}"
    return candidate_name


def _candidate_rows(optimization_result, top_n: int = 24):
    rows = []
    for candidate in optimization_result.all_results[:top_n]:
        rows.append(
            {
                "name": candidate.candidate_name,
                "optimization_method": _candidate_optimization_method(candidate.candidate_name),
                "score": round(candidate.score, 4),
                "gc_ratio": round(candidate.gc_ratio, 4),
                "max_homopolymer": candidate.max_homopolymer_run,
                "elapsed_ms": round(candidate.elapsed_ms, 3),
                "dna_length": candidate.dna_length,
            }
        )
    return rows


def _preview_base64(raw_bytes: bytes, max_chars: int = 120) -> str:
    encoded = base64.b64encode(raw_bytes).decode("ascii")
    if len(encoded) <= max_chars:
        return encoded
    return f"{encoded[:max_chars]}..."


def _size_profile(best_result, input_size: int):
    encrypted_size = len(best_result.encrypted_bytes)
    binary_bytes_equivalent = best_result.binary_bits // 8
    dna_text_size = best_result.dna_length
    rna_text_size = best_result.dna_length

    return {
        "input_bytes": input_size,
        "encrypted_bytes": encrypted_size,
        "binary_bytes_equivalent": binary_bytes_equivalent,
        "dna_text_bytes": dna_text_size,
        "rna_text_bytes": rna_text_size,
        "encryption_growth_ratio": round(encrypted_size / max(1, input_size), 4),
        "dna_vs_binary_ratio": round(dna_text_size / max(1, binary_bytes_equivalent), 4),
    }


def _score_profile(optimization_result, top_n: int = 10):
    score_rows = []
    for candidate in optimization_result.all_results[:top_n]:
        score_rows.append(
            {
                "name": candidate.candidate_name,
                "score": round(candidate.score, 4),
                "elapsed_ms": round(candidate.elapsed_ms, 3),
            }
        )
    return score_rows


def _base_payload(room: str, sender: str, receiver: str, optimization_result, input_size: int):
    best = optimization_result.best_result
    return {
        "room": room,
        "sender": sender,
        "receiver": receiver,
        "cipher_preview": encode_cipher_preview(best.encrypted_bytes),
        "best_method": best.candidate_name,
        "best_score": round(best.score, 4),
        "optimization_methods": optimization_result.optimization_methods,
        "compliance_trace": optimization_result.compliance_trace,
        "methods_evaluated": optimization_result.exhaustive_method_count,
        "comet_generations": optimization_result.comet_generation_count,
        "metrics": {
            "gc_ratio": round(best.gc_ratio, 4),
            "max_homopolymer": best.max_homopolymer_run,
            "elapsed_ms": round(best.elapsed_ms, 3),
            "binary_bits": best.binary_bits,
            "dna_length": best.dna_length,
        },
        "size_profile": _size_profile(best_result=best, input_size=input_size),
        "score_profile": _score_profile(optimization_result=optimization_result),
        "stage_trace": best.stage_trace,
        "candidate_table": _candidate_rows(optimization_result=optimization_result, top_n=24),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("join")
def handle_join(payload):
    room = payload.get("room", "demo-room").strip() or "demo-room"
    username = payload.get("username", "anonymous").strip() or "anonymous"

    join_room(room)
    room_members[room].add(username)

    emit(
        "presence",
        {
            "event": "join",
            "room": room,
            "username": username,
            "members": sorted(room_members[room]),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        to=room,
    )


@socketio.on("secure_message")
def handle_secure_message(payload):
    room = payload.get("room", "demo-room").strip() or "demo-room"
    sender = payload.get("sender", "Client-A").strip() or "Client-A"
    receiver = payload.get("receiver", "Client-B").strip() or "Client-B"
    plaintext = payload.get("plaintext", "")

    if not plaintext:
        emit("error_message", {"message": "Message cannot be empty."})
        return

    optimization = optimize_with_comet(message=plaintext, payload_type="text", iterations=3, comet_count=8)
    best = optimization.best_result

    event_payload = _base_payload(
        room=room,
        sender=sender,
        receiver=receiver,
        optimization_result=optimization,
        input_size=len(plaintext.encode("utf-8")),
    )
    event_payload.update(
        {
            "payload_kind": "text",
            "plaintext": plaintext,
            "decrypted_text": best.decrypted_bytes.decode("utf-8", errors="replace"),
            "transit_packet": {
                "kind": "encrypted-text",
                "encrypted_payload_preview_b64": _preview_base64(best.encrypted_bytes),
                "encrypted_sha256": hashlib.sha256(best.encrypted_bytes).hexdigest(),
                "encrypted_size": len(best.encrypted_bytes),
            },
        }
    )

    emit("secure_message_result", event_payload, to=room)


@socketio.on("secure_image")
def handle_secure_image(payload):
    room = payload.get("room", "demo-room").strip() or "demo-room"
    sender = payload.get("sender", "Client-A").strip() or "Client-A"
    receiver = payload.get("receiver", "Client-B").strip() or "Client-B"
    file_name = payload.get("file_name", "image.png")
    image_data_url = payload.get("image_data", "")

    if not image_data_url or "base64," not in image_data_url:
        emit("error_message", {"message": "Invalid image payload."})
        return

    header, encoded_data = image_data_url.split("base64,", 1)
    mime_type = "application/octet-stream"
    if header.startswith("data:") and ";" in header:
        mime_type = header[5:].split(";", 1)[0]

    try:
        image_bytes = base64.b64decode(encoded_data)
    except Exception:
        emit("error_message", {"message": "Image decode failed."})
        return

    optimization = optimize_with_comet(payload_bytes=image_bytes, payload_type="image", iterations=3, comet_count=8)
    best = optimization.best_result
    decrypted_b64 = base64.b64encode(best.decrypted_bytes).decode("ascii")

    event_payload = _base_payload(
        room=room,
        sender=sender,
        receiver=receiver,
        optimization_result=optimization,
        input_size=len(image_bytes),
    )
    event_payload.update(
        {
            "payload_kind": "image",
            "file_name": file_name,
            "mime_type": mime_type,
            "original_size": len(image_bytes),
            "decrypted_size": len(best.decrypted_bytes),
            "decrypted_image_data": f"data:{mime_type};base64,{decrypted_b64}",
            "transit_packet": {
                "kind": "encrypted-image",
                "encrypted_payload_preview_b64": _preview_base64(best.encrypted_bytes),
                "encrypted_sha256": hashlib.sha256(best.encrypted_bytes).hexdigest(),
                "encrypted_size": len(best.encrypted_bytes),
            },
        }
    )

    emit("secure_message_result", event_payload, to=room)


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
