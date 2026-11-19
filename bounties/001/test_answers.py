# /// script
# requires-python = ">=3.11"
# dependencies = ["argon2-cffi==25.1.0", "bech32==1.2.0"]
# ///
"""Exercise round 001 with real age encryption and a small test-only KDF."""

import hashlib
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import answers


class AnswerTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(
            dir=os.environ.get("TMPDIR") or Path.home() / "tmp"
        )
        self.addCleanup(temp.cleanup)
        self.public = Path(temp.name) / "public"
        self.private = Path(temp.name) / "private"
        self.public.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        keys = sorted(
            "2" * 42 + alphabet[i // 58] + alphabet[i % 58] for i in range(100)
        )
        names = [f"Sample {i}" for i in range(100)]
        (self.public / "voters.csv").write_text(
            "\n".join(f"{name},{key}" for name, key in zip(names, keys))
        )
        (self.public / "ballots.jsonl").write_bytes(b"test ballot fixture\n")
        options = ["opt-like"] * 60 + ["opt-unlike"] * 20 + ["opt-abstain"] * 20
        self.rows = [f"{name},{option}" for name, option in zip(names, options)]
        self.correct = "\n".join(self.rows).encode()
        self.owner = subprocess.run(
            ["age-keygen"], capture_output=True, check=True
        ).stdout
        self.recipient = answers._age(["age-keygen", "-y"], self.owner).decode().strip()
        self.addCleanup(patch.stopall)
        patch.object(answers, "_MEMORY_KIB", 1024).start()
        patch.object(answers, "_ITERATIONS", 1).start()

        self.payload = b"SUCCESS\n\x00\xff"
        self.secret = self.private / "payload.bin"
        self.secret.write_bytes(self.payload)

    def seal(self) -> None:
        answers._seal(
            self.public, self.private, self.recipient, self.correct, self.secret
        )
        names = ("voters.csv", "ballots.jsonl", "recipient.txt", "secret.age")
        (self.public / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256((self.public / name).read_bytes()).hexdigest()}  {name}\n"
                for name in names
            )
        )

    def test_derived_recipient_matches_reference(self) -> None:
        # Generated with system libargon2 and OpenSSL X25519 at 1 MiB, one pass.
        identity = answers._identity(b"Round 001 public test vector")
        self.assertEqual(
            answers._age(["age-keygen", "-y"], identity).strip(),
            b"age1j9gqq88nmrtxavl3rkpcf75gngz3gntc78fxatcr7llfywg2y9cqqdlup9",
        )

    def test_round_trip_and_output_permissions(self) -> None:
        self.seal()
        self.assertEqual(
            {p.name for p in self.public.iterdir()},
            {
                "voters.csv",
                "ballots.jsonl",
                "secret.age",
                "recipient.txt",
                "SHA256SUMS",
            },
        )
        backup = (self.private / "challenge-answer.csv.age").read_bytes()
        self.assertEqual(answers._decrypt(self.owner, backup), self.correct)
        shuffled = ("\ufeff" + "\r\n".join(reversed(self.rows)) + "\r\n").encode()
        answer = self.private / "answer.csv"
        output = self.private / "recovered.bin"
        answer.write_bytes(shuffled)
        args = ["answers.py", "open", str(self.public), str(answer), str(output)]
        status = io.StringIO()
        with patch("sys.argv", args), redirect_stdout(status):
            self.assertEqual(answers.main(), 0)
        self.assertNotIn("SUCCESS", status.getvalue())
        self.assertEqual(output.read_bytes(), self.payload)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        output.write_bytes(b"preserve")
        with patch("sys.argv", args), redirect_stderr(io.StringIO()):
            self.assertEqual(answers.main(), 1)
        self.assertEqual(output.read_bytes(), b"preserve")

    def test_wrong_answer_and_tampered_envelope(self) -> None:
        self.seal()
        wrong = self.rows.copy()
        wrong[0] = "Sample 0,opt-abstain"
        wrong[-1] = "Sample 99,opt-like"
        with self.assertRaises(answers.AnswerError):
            answers._open_secret(self.public, "\n".join(wrong).encode())
        (self.public / "secret.age").write_bytes(b"broken")
        with self.assertRaises(answers.AnswerError):
            answers._open_secret(self.public, self.correct)

    def test_secret_size(self) -> None:
        for data in (b"", b"x" * (answers._SECRET_LIMIT + 1)):
            self.secret.write_bytes(data)
            with self.assertRaises(answers.AnswerError):
                self.seal()
            self.assertFalse((self.public / "secret.age").exists())

    def test_checkout_source_secret_rejected(self) -> None:
        checkout = Path(answers.__file__).resolve().parents[2]
        with self.assertRaisesRegex(answers.AnswerError, "checkout"):
            answers._seal(
                self.public,
                self.private,
                self.recipient,
                self.correct,
                checkout / "Cargo.toml",
            )

    def test_private_input_rejects_shared_parent_and_file_symlink(self) -> None:
        shared = self.private / "shared-source"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        source = shared / "payload"
        source.write_bytes(b"secret")
        with self.assertRaisesRegex(answers.FixtureError, "owner-only"):
            answers._read_private(source, answers._SECRET_LIMIT, self.public)

        linked = self.private / "linked-payload"
        linked.symlink_to(self.secret)
        with self.assertRaises((answers.AnswerError, answers.FixtureError, OSError)):
            answers._read_private(linked, answers._SECRET_LIMIT, self.public)

        redirect = shared / "source-link"
        redirect.symlink_to(self.private, target_is_directory=True)
        with self.assertRaisesRegex(answers.FixtureError, "ancestry"):
            answers._read_private(
                redirect / self.secret.name, answers._SECRET_LIMIT, self.public
            )

    def test_private_input_fifo_rejected_without_waiting_for_writer(self) -> None:
        fifo = self.private / "answer.pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(answers.FixtureError, "regular file"):
            answers._read_private(fifo, answers._LIMIT, self.public)

    def test_checkout_output_rejected(self) -> None:
        checkout = Path(answers.__file__).resolve().parents[2]
        answer = self.private / "answer.csv"
        answer.write_bytes(self.correct)
        output = checkout / f".nazgul-bounty-test-{os.getpid()}.bin"
        self.assertFalse(output.exists())
        args = ["answers.py", "open", str(self.public), str(answer), str(output)]
        error = io.StringIO()
        with patch("sys.argv", args), redirect_stderr(error):
            self.assertEqual(answers.main(), 1)
        self.assertIn("checkout", error.getvalue())
        self.assertFalse(output.exists())

    def test_source_symlink_switch_cannot_read_checkout(self) -> None:
        safe = self.private / "safe-source"
        checkout = self.private / "fake-checkout"
        safe.mkdir(mode=0o700)
        checkout.mkdir(mode=0o700)
        (safe / "payload").write_bytes(b"safe")
        (checkout / "payload").write_bytes(b"checkout")
        redirect = self.private / "source-link"
        redirect.symlink_to(safe, target_is_directory=True)
        source = redirect / "payload"
        original_open = os.open

        def switch_before_open(path, *args, **kwargs):
            if path == source:
                redirect.unlink()
                redirect.symlink_to(checkout, target_is_directory=True)
            return original_open(path, *args, **kwargs)

        with (
            patch.object(answers, "_CHECKOUT", checkout),
            patch.object(os, "open", switch_before_open),
            self.assertRaisesRegex(answers.AnswerError, "checkout"),
        ):
            answers._seal(
                self.public, self.private, self.recipient, self.correct, source
            )
        self.assertFalse((self.public / "secret.age").exists())

    def test_output_symlink_switch_cannot_publish_to_checkout(self) -> None:
        safe = self.private / "safe-output"
        checkout = self.private / "fake-checkout"
        safe.mkdir(mode=0o700)
        checkout.mkdir()
        redirect = self.private / "output-link"
        redirect.symlink_to(safe, target_is_directory=True)
        output = redirect / "recovered.bin"
        answer = self.private / "answer.csv"
        answer.write_bytes(self.correct)

        def switch_after_validation(_public, _candidate):
            redirect.unlink()
            redirect.symlink_to(checkout, target_is_directory=True)
            return self.payload

        args = ["answers.py", "open", str(self.public), str(answer), str(output)]
        with (
            patch.object(answers, "_CHECKOUT", checkout),
            patch.object(answers, "_open_secret", side_effect=switch_after_validation),
            patch("sys.argv", args),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(answers.main(), 0)
        self.assertEqual((safe / "recovered.bin").read_bytes(), self.payload)
        self.assertFalse((checkout / "recovered.bin").exists())

    def test_answer_file_cannot_be_in_checkout(self) -> None:
        checkout = self.private / "fake-checkout"
        checkout.mkdir()
        answer = checkout / "answer.csv"
        answer.write_bytes(self.correct)
        args = ["answers.py", "check", str(self.public), str(answer)]
        error = io.StringIO()
        with (
            patch.object(answers, "_CHECKOUT", checkout),
            patch.object(answers, "_open_secret", return_value=self.payload),
            patch("sys.argv", args),
            redirect_stderr(error),
        ):
            self.assertEqual(answers.main(), 1)
        self.assertIn("checkout", error.getvalue())

    def test_output_parent_must_be_owner_only(self) -> None:
        self.seal()
        shared = self.private / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        answer = self.private / "answer.csv"
        answer.write_bytes(self.correct)
        output = shared / "recovered.bin"
        args = ["answers.py", "open", str(self.public), str(answer), str(output)]
        error = io.StringIO()
        with patch("sys.argv", args), redirect_stderr(error):
            self.assertEqual(answers.main(), 1)
        self.assertIn("owner-only", error.getvalue())
        self.assertFalse(output.exists())

    def test_public_changed_ciphertext_rejected(self) -> None:
        self.seal()
        secret = self.public / "secret.age"
        recipient = (self.public / "recipient.txt").read_text().strip()
        secret.write_bytes(answers._encrypt(recipient, b"SWAPPED"))
        with self.assertRaisesRegex(answers.AnswerError, "SHA256SUMS"):
            answers._open_secret(self.public, self.correct)

    def test_public_symlink_rejected(self) -> None:
        self.seal()
        secret = self.public / "secret.age"
        secret.unlink()
        secret.symlink_to("/dev/zero")
        with self.assertRaisesRegex(answers.AnswerError, "regular"):
            answers._open_secret(self.public, self.correct)

    def test_validation_and_no_overwrite(self) -> None:
        for rows in (
            self.rows[:-1],
            [*self.rows[:-1], self.rows[0]],
            [*self.rows[:-1], "Sample 99,opt-like"],
        ):
            with self.assertRaises(answers.AnswerError):
                answers._canonical(
                    (self.public / "voters.csv").read_bytes(), "\n".join(rows).encode()
                )
        envelope = self.public / "secret.age"
        envelope.write_bytes(b"retain me")
        with self.assertRaises((FileExistsError, answers.AnswerError)):
            self.seal()
        self.assertEqual(envelope.read_bytes(), b"retain me")
        self.assertFalse((self.public / "recipient.txt").exists())
        self.assertEqual(list(self.private.iterdir()), [self.secret])
        with self.assertRaises(answers.AnswerError):
            answers._seal(
                self.public, self.public, self.recipient, self.correct, self.secret
            )
        with self.assertRaises(answers.AnswerError):
            answers._bounded(io.BytesIO(b"a" * 12), 10)


if __name__ == "__main__":
    unittest.main()
