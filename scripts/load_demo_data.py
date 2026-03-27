import json
from pathlib import Path
from urllib import request

API = "http://127.0.0.1:8000/api/events/bulk"
DATA = Path(__file__).resolve().parents[1] / "data" / "sample_logs" / "demo_events.json"


def main() -> None:
    payload = {"events": json.loads(DATA.read_text(encoding="utf-8"))}
    req = request.Request(
        API,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req) as resp:
        print(resp.read().decode("utf-8"))


if __name__ == "__main__":
    main()
