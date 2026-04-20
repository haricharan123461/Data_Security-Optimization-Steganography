from pyngrok import ngrok
import time


def main() -> None:
    tunnel = ngrok.connect(5000, "http")
    print(f"NGROK_FORWARD_URL={tunnel.public_url}")
    print("Tunnel is active. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        try:
            ngrok.disconnect(tunnel.public_url)
        except Exception:
            pass
        print("Tunnel stopped.")


if __name__ == "__main__":
    main()
