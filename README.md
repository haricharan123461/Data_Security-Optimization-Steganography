# HelixShield Live

Real-time secure messaging and image sharing using AES encryption + DNA/RNA transformation with document-aligned COMET optimization.

## Key Features

- Live two-client communication over Socket.IO.
- Text and image payload encryption/decryption.
- DNA pipeline: bytes -> binary -> DNA -> RNA -> DNA -> binary -> bytes.
- Exhaustive DNA mapping evaluation ($4! = 24$ mappings).
- COMET (Characteristic Objects Method) implementation aligned to the provided paper (`Eq.16`-`Eq.23`).
- Hill-climbing local search refinement after COMET scoring.
- Side-panel visualization for:
	- Stage trace
	- Candidate table
	- Score/size charts
	- Encrypted-in-transit packet preview (Base64 + SHA-256)
	- Document compliance trace

## Project Structure

- `app.py`: Flask + Socket.IO server and event handlers.
- `dna_crypto.py`: AES and DNA/RNA conversion pipeline.
- `comet_optimizer.py`: COMET scoring + local refinement.
- `templates/index.html`: web interface.
- `static/app.js`: client-side socket logic and charts.
- `static/styles.css`: UI styling.
- `tests/test_protocol.py`: automated protocol tests.
- `ngrok_tunnel.py`: port forwarding utility.

## Setup and Run

```powershell
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Usage

1. Open two browser windows/tabs.
2. Join the same room with different client names.
3. Send text via **Encrypt + Send**.
4. Send image via **Encrypt + Send Image**.
5. Inspect side panel for optimization and compliance details.

## Run Tests

```powershell
python -m pytest tests/test_protocol.py -q
```

## ngrok (Cross-Device Access)

Terminal 1:

```powershell
python app.py
```

Terminal 2:

```powershell
python ngrok_tunnel.py
```

Use the printed `NGROK_FORWARD_URL` in other devices.

## Notes

- This project is for research/demo use.
- For production, add managed key exchange, authenticated encryption (e.g., AES-GCM), replay protection, and hardened deployment settings.
