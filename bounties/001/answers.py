# /// script
# requires-python = ">=3.11"
# dependencies = ["argon2-cffi==25.1.0", "bech32==1.2.0"]
# ///
"""Seal a test secret or check a round 001 answer. Use '-' for an answer on stdin."""

import argparse
import hashlib
import hmac
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from bech32 import bech32_encode, convertbits

__all__ = ["AnswerError", "main"]

_MEMORY_KIB = 4096 * 1024
_ITERATIONS = 120
_LIMIT = 128 * 1024
_SECRET_LIMIT = 64 * 1024
_COUNTS = {"opt-like": 60, "opt-unlike": 20, "opt-abstain": 20}
_CHECKOUT = Path(__file__).resolve().parents[2]


class AnswerError(ValueError):
    """The input or published envelope does not meet the round contract."""


def _bounded(source: BinaryIO, limit: int) -> bytes:
    data = source.read(limit + 1)
    if len(data) > limit:
        raise AnswerError("Input exceeds the round's size limit.")
    return data


def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        return _bounded(source, limit)


def _read_private(path: Path, limit: int, public: Path) -> bytes:
    # Check the opened object, then read that same FD despite path changes.
    with path.open("rb") as source:
        actual = Path(f"/proc/self/fd/{source.fileno()}").resolve(strict=True)
        if actual.is_relative_to(public) or actual.is_relative_to(_CHECKOUT):
            raise AnswerError(
                "Keep the answer and secret outside the public directory and checkout."
            )
        return _bounded(source, limit)


def _rows(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as exc:
        raise AnswerError("CSV must be UTF-8.") from exc
    rows: dict[str, str] = {}
    for line in text.rstrip("\n").split("\n"):
        fields = line.split(",")
        if len(fields) != 2:
            raise AnswerError("Expected exactly two CSV fields per row.")
        name, value = fields
        if (
            not name
            or not name.isascii()
            or not name.isprintable()
            or name.strip() != name
            or name in rows
        ):
            raise AnswerError("Invalid or duplicate voter name.")
        rows[name] = value
    return rows


def _canonical(public: Path, candidate: bytes) -> bytes:
    voters = _rows(_read(public / "voters.csv", _LIMIT))
    keys = list(voters.values())
    if (
        len(voters) != sum(_COUNTS.values())
        or keys != sorted(set(keys))
        or any(not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", key) for key in keys)
    ):
        raise AnswerError("Invalid public voter roster.")
    choices = _rows(candidate)
    if choices.keys() != voters.keys() or Counter(choices.values()) != _COUNTS:
        raise AnswerError(
            "Answer must cover every voter and match the published option counts."
        )
    return "\n".join(f"{name},{choices[name]}" for name in voters).encode("ascii")


def _identity(canonical: bytes) -> bytes:
    raw = hash_secret_raw(
        hashlib.sha3_512(canonical).digest(),
        b"nazgul-bounty-001",
        _ITERATIONS,
        _MEMORY_KIB,
        1,
        32,
        Type.ID,
        version=19,
    )
    words = convertbits(raw, 8, 5)
    if words is None:
        raise AnswerError("Failed to encode the derived age identity.")
    return (bech32_encode("age-secret-key-", words).upper() + "\n").encode("ascii")


def _age(args: list[str], data: bytes, pass_fds: tuple[int, ...] = ()) -> bytes:
    try:
        result = subprocess.run(
            args,
            input=data,
            capture_output=True,
            check=True,
            timeout=30,
            pass_fds=pass_fds,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise AnswerError(f"{args[0]} failed to process the envelope.") from exc
    return result.stdout


def _encrypt(recipient: str, plaintext: bytes) -> bytes:
    if not re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", recipient):
        raise AnswerError("Expected an age X25519 recipient.")
    return _age(["age", "--encrypt", "-r", recipient], plaintext)


def _decrypt(identity: bytes, ciphertext: bytes) -> bytes:
    # The identity travels through stdin; only ciphertext goes into the anonymous file.
    with os.fdopen(os.memfd_create("nazgul-ciphertext"), "w+b") as source:
        source.write(ciphertext)
        source.seek(0)
        fd = source.fileno()
        return _age(
            ["age", "--decrypt", "-i", "-", f"/proc/self/fd/{fd}"], identity, (fd,)
        )


def _open_secret(public: Path, candidate: bytes) -> bytes:
    expected = _read(public / "recipient.txt", 128)
    ciphertext = _read(public / "secret.age", _SECRET_LIMIT + 4096)
    identity = _identity(_canonical(public, candidate))
    if not hmac.compare_digest(expected, _age(["age-keygen", "-y"], identity)):
        raise AnswerError("Answer does not match the published recipient.")
    secret = _decrypt(identity, ciphertext)
    if not 0 < len(secret) <= _SECRET_LIMIT:
        raise AnswerError("Invalid secret size.")
    return secret


def _publish(path: Path, payload: bytes, rollback: ExitStack) -> None:
    # A hard link exposes the complete file atomically and refuses an occupied name.
    with tempfile.NamedTemporaryFile(dir=path.parent) as staged:
        staged.write(payload)
        staged.flush()
        os.fsync(staged.fileno())
        os.link(staged.name, path)
        rollback.callback(path.unlink)


def _open_to(public: Path, candidate: bytes, output: Path) -> None:
    if output.name in ("", ".", ".."):
        raise AnswerError("Expected a new output file name.")
    parent_fd = os.open(output.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        directory = Path(f"/proc/self/fd/{parent_fd}")
        actual = directory.resolve(strict=True)
        if actual.is_relative_to(public) or actual.is_relative_to(_CHECKOUT):
            raise AnswerError(
                "Write the plaintext outside the public directory and checkout."
            )
        target = directory / output.name
        if os.path.lexists(target):
            raise AnswerError("Output file already exists.")
        secret = _open_secret(public, candidate)
        with ExitStack() as rollback:
            _publish(target, secret, rollback)
            rollback.pop_all()
    finally:
        os.close(parent_fd)


def _seal(
    public: Path, private: Path, organizer: str, candidate: bytes, secret_path: Path
) -> None:
    public, private = public.resolve(strict=True), private.resolve(strict=True)
    if (
        public.is_relative_to(private)
        or private.is_relative_to(public)
        or private.stat().st_mode & 0o077
    ):
        raise AnswerError("Use separate public and owner-only private directories.")
    backup = private / "challenge-answer.csv.age"
    envelope = public / "secret.age"
    recipient = public / "recipient.txt"
    if any(os.path.lexists(path) for path in (backup, envelope, recipient)):
        raise AnswerError("A seal artifact already exists.")
    secret = _read_private(secret_path, _SECRET_LIMIT, public)
    if not secret:
        raise AnswerError("Secret must contain at least one byte.")
    canonical = _canonical(public, candidate)
    identity = _identity(canonical)
    target = _age(["age-keygen", "-y"], identity)
    ciphertext = _encrypt(target.decode("ascii").strip(), secret)
    if not hmac.compare_digest(_decrypt(identity, ciphertext), secret):
        raise AnswerError("Generated secret envelope failed its round-trip check.")
    with ExitStack() as rollback:
        _publish(backup, _encrypt(organizer, canonical), rollback)
        _publish(envelope, ciphertext, rollback)
        _publish(recipient, target, rollback)
        rollback.pop_all()


def main() -> int:
    """Seal, verify or open the secret envelope for a known-answer round."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("seal")
    seal.add_argument("public", type=Path)
    seal.add_argument("private", type=Path)
    seal.add_argument("organizer")
    seal.add_argument("secret", type=Path)
    for name in ("check", "open"):
        command = commands.add_parser(name)
        command.add_argument("public", type=Path)
        command.add_argument("answer", type=Path, help="answer CSV, or - for stdin")
        if name == "open":
            command.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "seal":
            _seal(
                args.public,
                args.private,
                args.organizer,
                _bounded(sys.stdin.buffer, _LIMIT),
                args.secret,
            )
            print("Answer and secret sealed.")
        else:
            public = args.public.resolve(strict=True)
            candidate = (
                _bounded(sys.stdin.buffer, _LIMIT)
                if args.answer == Path("-")
                else _read_private(args.answer, _LIMIT, public)
            )
            if args.command == "open":
                _open_to(public, candidate, args.output)
                print("Secret written.")
            else:
                _open_secret(public, candidate)
                print("Answer verified.")
    except (
        AnswerError,
        OSError,
        HashingError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
