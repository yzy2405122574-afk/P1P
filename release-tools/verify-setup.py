import argparse
import base64
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile


MANIFEST_LIMIT = 16 * 1024
PACKAGE_LIMIT = 128 * 1024 * 1024
VERSION = r"(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})"
ASSETS = {"TURBO-Setup.exe", "turbo.exe", "latest.json"}


def read_version(version):
    match = re.fullmatch(VERSION, version)
    if match is None:
        raise ValueError("Expected a three-part TURBO version.")
    parts = tuple(map(int, match.groups()))
    if any(part > 2147483647 for part in parts):
        raise ValueError("Version exceeds the Windows version range.")
    return parts


def decode_manifest(manifest, public_key, openssl):
    envelope = json.loads(manifest)
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    with TemporaryDirectory(prefix="turbo-signature-") as directory:
        input_file = Path(directory, "payload")
        signature_file = Path(directory, "signature")
        input_file.write_bytes(payload)
        signature_file.write_bytes(signature)
        result = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(public_key),
             "-signature", str(signature_file), str(input_file)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError("The release manifest is not signed by the TURBO update key.")
    return json.loads(payload)


def copy_verified(archive, info, destination, checksum):
    if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-fA-F]{64}", checksum) is None:
        raise ValueError(f"The signed SHA-256 is missing for {info.filename}.")
    digest = hashlib.sha256()
    received = 0
    with archive.open(info) as source, destination.open("xb") as output:
        for block in iter(lambda: source.read(65536), b""):
            received += len(block)
            if received > info.file_size:
                raise ValueError(f"{info.filename} exceeded its declared size.")
            digest.update(block)
            output.write(block)
    if received != info.file_size or digest.hexdigest() != checksum.lower():
        raise ValueError(f"The SHA-256 or size of {info.filename} does not match the signed manifest.")


def verify(package, output, public_key, openssl, latest):
    match = re.fullmatch(rf"TURBO-v({VERSION})-Setup\.zip", package.name)
    if match is None:
        raise ValueError("Expected TURBO-v<version>-Setup.zip.")
    version = match[1]
    parts = read_version(version)
    if latest and parts <= read_version(latest.removeprefix("v")):
        raise ValueError(f"v{version} must be newer than the current release {latest}.")

    with ZipFile(package) as archive:
        entries = archive.infolist()
        if len(entries) != len(ASSETS) or {entry.filename for entry in entries} != ASSETS:
            raise ValueError("The ZIP must contain TURBO-Setup.exe, turbo.exe and latest.json at the root.")
        files = {entry.filename: entry for entry in entries}
        for name, entry in files.items():
            file_type = stat.S_IFMT(entry.external_attr >> 16)
            limit = MANIFEST_LIMIT if name == "latest.json" else PACKAGE_LIMIT
            if file_type not in (0, stat.S_IFREG) or not 0 < entry.file_size <= limit:
                raise ValueError(f"Invalid size or file type for {name}.")

        manifest = archive.read(files["latest.json"])
        metadata = decode_manifest(manifest, public_key, openssl)
        if metadata["product"] != "TURBO" or metadata["file"] != "turbo.exe" or metadata["version"] != version:
            raise ValueError("The signed product or version does not match the ZIP filename.")
        published = metadata["published"]
        if date.fromisoformat(published).isoformat() != published:
            raise ValueError("Invalid release date in the signed manifest.")
        if type(metadata["size"]) is not int or metadata["size"] != files["turbo.exe"].file_size:
            raise ValueError("The signed size of turbo.exe does not match the ZIP.")
        notes = metadata.get("notes", "")
        if not isinstance(notes, str) or len(notes) > 1200:
            raise ValueError("Invalid release notes in the signed manifest.")

        with TemporaryDirectory(prefix="verified-", dir=output.parent) as directory:
            staging = Path(directory)
            copy_verified(archive, files["turbo.exe"], staging / "turbo.exe", metadata["sha256"])
            copy_verified(archive, files["TURBO-Setup.exe"], staging / "TURBO-Setup.exe", metadata["setup_sha256"])
            (staging / "latest.json").write_bytes(manifest)
            (staging / "release-notes.txt").write_text(notes.strip() + "\n", encoding="utf-8")
            output.mkdir()
            for name in ("turbo.exe", "latest.json", "release-notes.txt"):
                (staging / name).rename(output / name)
    print(f"v{version}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--latest", default="")
    args = parser.parse_args()
    try:
        verify(args.package, args.output, args.public_key, args.openssl, args.latest)
    except (BadZipFile, OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        parser.exit(1, f"Invalid TURBO setup bundle. {error}\n")


if __name__ == "__main__":
    main()
