"""Benchmark fast-paseto against other Python PASETO/JWT libraries.

Usage
-----
    python profiling/benchmark.py                # run everything, print table
    python profiling/benchmark.py --only pyseto  # run a subset
    python profiling/benchmark.py --worker pyseto  # internal: single-library run

Why subprocesses
----------------
``python-paseto`` (purificant) and ``pypaseto`` (rlittlefield) both publish a
top-level ``paseto`` module, so they cannot be installed side by side. Each
library is therefore measured in its own throwaway environment created by
``uv run --no-project --with <requirement>``, and the results come back as JSON
on stdout. fast-paseto is measured in the current interpreter, which is expected
to be the project venv with a *release* build installed.

Everything is measured against the same logical operations so the numbers line
up across libraries:

    keygen_symmetric   produce a fresh symmetric key
    keygen_keypair     produce a fresh signing keypair
    local_encode       serialize claims -> encrypted/symmetric token
    local_decode       symmetric token -> claims
    public_encode      serialize claims -> signed token
    public_decode      verify signed token -> claims

Caveats worth remembering when reading the output:

* PyJWT is a JWT library, not PASETO. Its "local" rows are HS256 (signed,
  *not* encrypted), so they are not a like-for-like security comparison.
* ``python-paseto`` exposes a bytes-in/bytes-out low level API only, so the
  JSON encode/decode of the claims is included explicitly to keep it fair.
* ``python-paseto`` and ``pypaseto`` both need a system ``libsodium``. Without
  it they are reported as unavailable rather than silently skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared configuration
# ---------------------------------------------------------------------------

PAYLOAD: dict[str, object] = {
    "sub": "user-1234",
    "role": "admin",
    "scopes": ["read", "write"],
}

BASELINE = "fast-paseto"

OPERATIONS: tuple[tuple[str, str], ...] = (
    ("keygen_symmetric", "generate symmetric key"),
    ("keygen_keypair", "generate keypair"),
    ("local_encode", "v4.local encode"),
    ("local_decode", "v4.local decode"),
    ("public_encode", "v4.public encode (sign)"),
    ("public_decode", "v4.public decode (verify)"),
)

# library name -> pip requirements for its isolated environment.
# An empty tuple means "use the current interpreter" (fast-paseto).
LIBRARIES: dict[str, tuple[str, ...]] = {
    "fast-paseto": (),
    "pyseto": ("pyseto", "cryptography"),
    "python-paseto": ("python-paseto",),
    "pypaseto": ("paseto",),
    "pyjwt": ("pyjwt", "cryptography"),
}

MIN_SAMPLE_SECONDS = 0.2
REPEATS = 5


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------


def measure(func) -> float:
    """Return the best per-call duration of ``func`` in seconds.

    Loop count is calibrated so a single sample runs for at least
    ``MIN_SAMPLE_SECONDS``, which keeps sub-microsecond operations out of clock
    resolution noise. The minimum across repeats is reported because it is the
    sample least polluted by unrelated system activity.
    """
    func()  # warm up caches / lazy imports

    loops = 1
    while True:
        start = time.perf_counter()
        for _ in range(loops):
            func()
        elapsed = time.perf_counter() - start
        if elapsed >= MIN_SAMPLE_SECONDS:
            break
        loops *= 10

    best = elapsed / loops
    for _ in range(REPEATS - 1):
        start = time.perf_counter()
        for _ in range(loops):
            func()
        best = min(best, (time.perf_counter() - start) / loops)
    return best


# ---------------------------------------------------------------------------
# Per-library operation builders
#
# Each builder returns {operation_name: zero-arg callable}. Raising is fine:
# the worker turns it into an "unavailable" result with the reason attached.
# ---------------------------------------------------------------------------


def build_fast_paseto():
    import fast_paseto

    key = fast_paseto.generate_symmetric_key()
    secret_key, public_key = fast_paseto.generate_keypair()
    local_token = fast_paseto.encode(key, PAYLOAD, purpose="local", version="v4")
    public_token = fast_paseto.encode(
        secret_key, PAYLOAD, purpose="public", version="v4"
    )

    return {
        "keygen_symmetric": fast_paseto.generate_symmetric_key,
        "keygen_keypair": fast_paseto.generate_keypair,
        "local_encode": lambda: fast_paseto.encode(
            key, PAYLOAD, purpose="local", version="v4"
        ),
        "local_decode": lambda: fast_paseto.decode(
            local_token, key, purpose="local", version="v4"
        ),
        "public_encode": lambda: fast_paseto.encode(
            secret_key, PAYLOAD, purpose="public", version="v4"
        ),
        "public_decode": lambda: fast_paseto.decode(
            public_token, public_key, purpose="public", version="v4"
        ),
    }


def build_pyseto():
    import secrets

    import pyseto
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from pyseto import Key

    def keygen_symmetric():
        return Key.new(version=4, purpose="local", key=secrets.token_bytes(32))

    def keygen_keypair():
        # pyseto has no keypair generator; it consumes PEM, so this is the
        # cheapest path from "nothing" to a usable pyseto signing keypair.
        private = Ed25519PrivateKey.generate()
        secret_pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return (
            Key.new(version=4, purpose="public", key=secret_pem),
            Key.new(version=4, purpose="public", key=public_pem),
        )

    local_key = keygen_symmetric()
    secret_key, public_key = keygen_keypair()
    local_token = pyseto.encode(local_key, PAYLOAD, serializer=json)
    public_token = pyseto.encode(secret_key, PAYLOAD, serializer=json)

    return {
        "keygen_symmetric": keygen_symmetric,
        "keygen_keypair": keygen_keypair,
        "local_encode": lambda: pyseto.encode(local_key, PAYLOAD, serializer=json),
        "local_decode": lambda: pyseto.decode(
            local_key, local_token, deserializer=json
        ),
        "public_encode": lambda: pyseto.encode(secret_key, PAYLOAD, serializer=json),
        "public_decode": lambda: pyseto.decode(
            public_key, public_token, deserializer=json
        ),
    }


def require_libsodium() -> None:
    """Fail with an actionable message when libsodium is not loadable.

    ``pysodium`` resolves libsodium through ``ctypes.util.find_library`` at
    import time and raises an opaque ``TypeError`` when it comes back empty, so
    check up front and say what is actually wrong.

    On Windows ``find_library`` only scans ``PATH``, so ``LIBSODIUM_DIR`` is
    honoured as an escape hatch for a libsodium.dll kept outside PATH.
    """
    import ctypes.util

    sodium_dir = os.environ.get("LIBSODIUM_DIR")
    if sodium_dir:
        os.environ["PATH"] = sodium_dir + os.pathsep + os.environ.get("PATH", "")

    if ctypes.util.find_library("sodium") or ctypes.util.find_library("libsodium"):
        return
    raise RuntimeError(
        "libsodium is not installed or not on the library search path. "
        "This library binds it through pysodium/ctypes. "
        "Linux: apt install libsodium23 | macOS: brew install libsodium | "
        "Windows: put libsodium.dll on PATH or set LIBSODIUM_DIR to its folder."
    )


def build_python_paseto():
    require_libsodium()

    from paseto.protocol.version4 import (
        create_asymmetric_key,
        create_symmetric_key,
        decrypt,
        encrypt,
        sign,
        verify,
    )

    message = json.dumps(PAYLOAD).encode()
    local_key = create_symmetric_key()
    public_key, secret_key = create_asymmetric_key()
    local_token = encrypt(message, local_key)
    public_token = sign(message, secret_key)

    return {
        "keygen_symmetric": create_symmetric_key,
        "keygen_keypair": create_asymmetric_key,
        "local_encode": lambda: encrypt(json.dumps(PAYLOAD).encode(), local_key),
        "local_decode": lambda: json.loads(decrypt(local_token, local_key)),
        "public_encode": lambda: sign(json.dumps(PAYLOAD).encode(), secret_key),
        "public_decode": lambda: json.loads(verify(public_token, public_key)),
    }


def build_pypaseto():
    require_libsodium()

    import paseto
    from paseto.keys.asymmetric_key import AsymmetricSecretKey
    from paseto.keys.symmetric_key import SymmetricKey
    from paseto.protocols.v4 import ProtocolVersion4

    def keygen_symmetric():
        return SymmetricKey.generate(protocol=ProtocolVersion4)

    def keygen_keypair():
        return AsymmetricSecretKey.generate(protocol=ProtocolVersion4)

    local_key = keygen_symmetric()
    # pypaseto's parse() takes the secret key for public tokens and derives the
    # public half itself, so there is no separate verification key here.
    secret_key = keygen_keypair()

    local_token = paseto.create(key=local_key, purpose="local", claims=dict(PAYLOAD))
    public_token = paseto.create(key=secret_key, purpose="public", claims=dict(PAYLOAD))

    return {
        "keygen_symmetric": keygen_symmetric,
        "keygen_keypair": keygen_keypair,
        "local_encode": lambda: paseto.create(
            key=local_key, purpose="local", claims=dict(PAYLOAD)
        ),
        "local_decode": lambda: paseto.parse(
            key=local_key, purpose="local", token=local_token
        ),
        "public_encode": lambda: paseto.create(
            key=secret_key, purpose="public", claims=dict(PAYLOAD)
        ),
        "public_decode": lambda: paseto.parse(
            key=secret_key, purpose="public", token=public_token
        ),
    }


def build_pyjwt():
    import secrets

    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    hs_key = secrets.token_bytes(32)
    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    hs_token = jwt.encode(PAYLOAD, hs_key, algorithm="HS256")
    ed_token = jwt.encode(PAYLOAD, private, algorithm="EdDSA")

    def keygen_keypair():
        key = Ed25519PrivateKey.generate()
        return key, key.public_key()

    return {
        "keygen_symmetric": lambda: secrets.token_bytes(32),
        "keygen_keypair": keygen_keypair,
        "local_encode": lambda: jwt.encode(PAYLOAD, hs_key, algorithm="HS256"),
        "local_decode": lambda: jwt.decode(hs_token, hs_key, algorithms=["HS256"]),
        "public_encode": lambda: jwt.encode(PAYLOAD, private, algorithm="EdDSA"),
        "public_decode": lambda: jwt.decode(ed_token, public, algorithms=["EdDSA"]),
    }


BUILDERS = {
    "fast-paseto": build_fast_paseto,
    "pyseto": build_pyseto,
    "python-paseto": build_python_paseto,
    "pypaseto": build_pypaseto,
    "pyjwt": build_pyjwt,
}


# ---------------------------------------------------------------------------
# Worker: benchmark one library, emit JSON
# ---------------------------------------------------------------------------


def run_worker(name: str) -> dict:
    result: dict = {"library": name, "timings": {}, "errors": {}}
    try:
        operations = BUILDERS[name]()
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        result["unavailable"] = f"{type(exc).__name__}: {exc}"
        result["traceback"] = traceback.format_exc()
        return result

    for key, _label in OPERATIONS:
        func = operations.get(key)
        if func is None:
            result["errors"][key] = "not supported"
            continue
        try:
            result["timings"][key] = measure(func)
        except Exception as exc:  # noqa: BLE001
            result["errors"][key] = f"{type(exc).__name__}: {exc}"
    return result


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

MARKER = "###BENCHMARK_JSON###"


def spawn(name: str, requirements: tuple[str, ...], script: Path) -> dict:
    if requirements:
        command = ["uv", "run", "--no-project", "--quiet"]
        for requirement in requirements:
            command += ["--with", requirement]
        command += ["python", str(script), "--worker", name]
    else:
        command = [sys.executable, str(script), "--worker", name]

    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        cwd=script.parent.parent,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )

    for line in proc.stdout.splitlines():
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER) :])

    detail = (proc.stderr or proc.stdout or "no output").strip().splitlines()
    return {
        "library": name,
        "timings": {},
        "errors": {},
        "unavailable": f"worker failed (exit {proc.returncode}): "
        + (detail[-1] if detail else "no output"),
    }


def format_duration(seconds: float) -> str:
    micros = seconds * 1_000_000
    if micros < 10:
        return f"{micros:.2f} us"
    if micros < 100:
        return f"{micros:.1f} us"
    return f"{micros:.0f} us"


def render(results: list[dict]) -> str:
    baseline = next((r for r in results if r["library"] == BASELINE), None)
    available = [r for r in results if not r.get("unavailable")]
    unavailable = [r for r in results if r.get("unavailable")]

    names = [r["library"] for r in available]
    lines: list[str] = []

    if not names:
        return "No library could be benchmarked.\n" + "\n".join(
            f"  - {r['library']}: {r['unavailable']}" for r in unavailable
        )

    header = ["Operation", *names]
    if baseline is not None and len(names) > 1:
        header += [f"{n} vs {BASELINE}" for n in names if n != BASELINE]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")

    for key, label in OPERATIONS:
        row = [label]
        for r in available:
            timing = r["timings"].get(key)
            row.append(
                format_duration(timing)
                if timing is not None
                else r["errors"].get(key, "n/a")
            )
        if baseline is not None and len(names) > 1:
            base = baseline["timings"].get(key)
            for r in available:
                if r["library"] == BASELINE:
                    continue
                other = r["timings"].get(key)
                if base and other:
                    row.append(f"{other / base:.1f}x")
                else:
                    row.append("n/a")
        lines.append("| " + " | ".join(row) + " |")

    if unavailable:
        lines.append("")
        lines.append("Unavailable:")
        for r in unavailable:
            lines.append(f"  - {r['library']}: {r['unavailable']}")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--worker",
        choices=sorted(LIBRARIES),
        help="internal: benchmark a single library and emit JSON",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        choices=sorted(LIBRARIES),
        help="benchmark only these libraries",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="also write raw timings to this JSON file",
    )
    args = parser.parse_args()

    if args.worker:
        print(MARKER + json.dumps(run_worker(args.worker)))
        return 0

    script = Path(__file__).resolve()
    selected = args.only or list(LIBRARIES)

    print(f"Python {platform.python_version()} on {platform.platform()}")
    print(f"CPU: {platform.processor() or 'unknown'}")
    print()

    results = []
    for name in selected:
        print(f"benchmarking {name} ...", file=sys.stderr, flush=True)
        results.append(spawn(name, LIBRARIES[name], script))

    print(render(results))

    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nRaw timings written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
