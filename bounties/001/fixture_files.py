"""Bounded public fixture reads and safe directories for round 001."""

import argparse
import errno
import hashlib
import os
import stat
import sys
from pathlib import Path

__all__ = ["FixtureError", "main", "read_public", "require_safe_directory"]

_FILES = (
    ("voters.csv", 128 * 1024),
    ("ballots.jsonl", 4 * 1024 * 1024),
    ("recipient.txt", 128),
    ("secret.age", 64 * 1024 + 4096),
    ("SHA256SUMS", 1024),
)


class FixtureError(ValueError):
    """A fixture file or directory violates the round's filesystem contract."""


def require_safe_directory(path: Path, *, private: bool = False) -> Path:
    """Require owner-controlled ancestry; private leaves must be owner-only."""
    resolved = path.resolve(strict=True)
    uid = os.geteuid()
    leaf = resolved.stat()
    if private and (leaf.st_uid != uid or leaf.st_mode & 0o077):
        raise FixtureError("Use an owner-only private directory.")
    for ancestor in (resolved, *resolved.parents):
        info = ancestor.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
            raise FixtureError("Use directories owned by this user or root.")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise FixtureError("Use directory ancestry that other users cannot rename.")
    return resolved


def read_public(public: Path) -> dict[str, bytes]:
    """Read bounded regular files through one directory FD and verify the manifest."""
    root_fd = os.open(public, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        files: dict[str, bytes] = {}
        for name, limit in _FILES:
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise FixtureError(
                        "Public artifacts must be regular files without links."
                    ) from exc
                raise
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise FixtureError("Public artifacts must be regular files.")
                if info.st_size > limit:
                    raise FixtureError(
                        f"Public artifact {name} exceeds its size limit."
                    )
                data = source.read(limit + 1)
                if len(data) > limit:
                    raise FixtureError(
                        f"Public artifact {name} exceeds its size limit."
                    )
                files[name] = data
        expected = b"".join(
            f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n".encode("ascii")
            for name, _ in _FILES[:-1]
        )
        if files["SHA256SUMS"] != expected:
            raise FixtureError("Public SHA256SUMS does not match artifact bytes.")
        return files
    finally:
        os.close(root_fd)


def main() -> int:
    """Check safe parents or copy a verified fixture to a private snapshot."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("safe-parent", "private-dir", "snapshot"))
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "safe-parent":
            for path in args.paths:
                require_safe_directory(path)
        elif args.action == "private-dir":
            for path in args.paths:
                require_safe_directory(path, private=True)
        else:
            if len(args.paths) != 2:
                parser.error("snapshot requires PUBLIC_DIR and PRIVATE_DIR")
            destination = require_safe_directory(args.paths[1], private=True)
            files = read_public(args.paths[0])
            for name, data in files.items():
                fd = os.open(
                    destination / name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                )
                with os.fdopen(fd, "wb") as target:
                    target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
    except (FixtureError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
