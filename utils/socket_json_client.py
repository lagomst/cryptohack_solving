# file: socket_json_client.py
"""
Minimal JSON-over-TCP client using pwntools.
Fixes ImportError: do NOT import TimeoutError/EOFError from `pwn`.
Usage example:
  python socket_json_client.py --host socket.cryptohack.org --port 13382 \
    --data '{"hello":"world"}' --out interceptor.txt
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from pwn import remote  # only import what we actually use


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def json_send(r, obj: Any) -> None:
    payload = json.dumps(obj, separators=(",", ":")).encode()
    r.sendline(payload)


def json_recv(r, timeout: float = 5.0) -> Optional[dict]:
    """
    Attempt to read one newline-terminated line and parse as JSON.
    Uses broad exception handling so we don't rely on specific pwntools exception names.
    Returns parsed dict on success, None on any failure.
    """
    try:
        raw = r.recvline(timeout=timeout)
        if not raw:
            eprint("recvline returned empty/None (no data).")
            return None
        if isinstance(raw, bytes):
            raw = raw.decode(errors="replace")
        raw = raw.strip()
        if not raw:
            eprint("Received line is empty after stripping.")
            return None
        return json.loads(raw)
    except json.JSONDecodeError:
        eprint("Received non-JSON / malformed JSON:", repr(raw))
        return None
    except Exception as exc:
        # pwntools raises various exception types depending on situation/version.
        # Handle common cases by message content (robust across versions).
        msg = str(exc).lower()
        if "timed out" in msg or "timeout" in msg:
            eprint(f"Timed out after {timeout} seconds waiting for a reply.")
        elif "eof" in msg or "closed" in msg:
            eprint("Connection closed by remote while waiting for a reply.")
        else:
            eprint("Error while receiving:", exc)
        return None

def stream_json_recv(r, timeout: float = 5.0) -> Optional[dict]:
    try:
        raw = r.recvline(timeout=timeout)
        if not raw:
            eprint("recvline returned empty/None (no data).")
            return None
        if isinstance(raw, bytes):
            raw = raw.decode(errors="replace")
        raw = raw.strip()
        if not raw:
            eprint("Received line is empty after stripping.")
            return None
        raw = raw[raw.find('{'):]
        return json.load(raw)
        
    except json.JSONDecodeError:
        eprint("Received non-JSON / malformed JSON:", repr(raw))
        return None
    except Exception as exc:
        # pwntools raises various exception types depending on situation/version.
        # Handle common cases by message content (robust across versions).
        msg = str(exc).lower()
        if "timed out" in msg or "timeout" in msg:
            eprint(f"Timed out after {timeout} seconds waiting for a reply.")
        elif "eof" in msg or "closed" in msg:
            eprint("Connection closed by remote while waiting for a reply.")
        else:
            eprint("Error while receiving:", exc)
        return None

def read_banner_lines(r, count: int = 4, timeout: float = 0.8) -> None:
    for _ in range(count):
        try:
            line = r.recvline(timeout=timeout)
            if not line:
                break
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            print(line.rstrip("\n"))
        except Exception:
            # stop reading more banner lines if anything goes wrong or times out
            break

DEFAULT_DATA = {
    "private_key": 1,
    "host": "www.bing.com",
    "curve": "p256",
    "generator": ()
}

def load_request_from_args(args: argparse.Namespace) -> Any:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    if args.data:
        return json.loads(args.data)
    return DEFAULT_DATA

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Send one JSON line to TCP socket and read one JSON reply.")
    p.add_argument("--host", "-H", default="socket.cryptohack.org")
    p.add_argument("--port", "-P", default=13382, type=int)
    group = p.add_mutually_exclusive_group()
    group.add_argument("--data", "-d", help='JSON string to send (e.g. \'{"a":1}\')')
    group.add_argument("--file", "-f", help="path to a JSON file to send")
    p.add_argument("--out", "-o", default="interceptor.txt")
    p.add_argument("--banner-lines", type=int, default=4)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--interactive", "-i", action="store_true")
    args = p.parse_args(argv)

    try:
        request = load_request_from_args(args)
    except json.JSONDecodeError as exc:
        eprint("Failed to parse JSON for --data or --file:", exc)
        return 2

    eprint(f"Connecting to {args.host}:{args.port} ...")
    try:
        r = remote(args.host, args.port)
    except Exception as exc:
        eprint("Failed to open remote connection:", exc)
        return 3

    read_banner_lines(r, count=args.banner_lines, timeout=0.8)

    try:
        json_send(r, request)
    except Exception as exc:
        eprint("Failed to send JSON:", exc)
        r.close()
        return 4

    response = json_recv(r, timeout=args.timeout)

    if response is None:
        eprint("No valid JSON response received.")
    else:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(response, fh, indent=2, ensure_ascii=False)
            print("Saved reply to", args.out)
            print(json.dumps(response, indent=2, ensure_ascii=False))
        except Exception as exc:
            eprint("Failed to write reply to file:", exc)

    if args.interactive:
        eprint("Dropping to interactive mode. Ctrl-C to exit.")
        try:
            r.interactive()
        except Exception as exc:
            eprint("Interactive session ended / error:", exc)

    r.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
