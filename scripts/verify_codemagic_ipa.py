#!/usr/bin/env python3
"""Validate an unsigned device IPA before it becomes a downloadable candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import zipfile

def verify(args):
    ipa = Path(args.ipa)
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError("Expected a full source commit SHA")
    root = "Payload/" + args.app_name + ".app/"
    with zipfile.ZipFile(ipa) as archive:
        if archive.testzip() is not None:
            raise ValueError("IPA integrity check failed")
        info = plistlib.loads(archive.read(root + "Info.plist"))
        expected = {
            "CFBundleIdentifier": args.bundle_id,
            "CFBundleShortVersionString": args.version,
            "CFBundleVersion": args.build,
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        for key, value in expected.items():
            if info.get(key) != value:
                raise ValueError("Unexpected bundle metadata: " + key)
        def os_version(value):
            parts = str(value).split(".")
            if not parts or len(parts) > 3 or any(not part.isdigit() for part in parts):
                raise ValueError("Invalid minimum OS version")
            return tuple(int(part) for part in parts) + (0,) * (3 - len(parts))
        if os_version(info.get("MinimumOSVersion", "")) < os_version(args.minimum_os):
            raise ValueError("Minimum OS is below the release floor")
        binary = archive.read(root + info["CFBundleExecutable"])
        if len(binary) < 32:
            raise ValueError("Missing Mach-O header")
        magic, cpu, _, filetype, commands, command_bytes, _, _ = struct.unpack_from("<8I", binary)
        if magic != 0xfeedfacf or cpu != 0x0100000c or filetype != 2:
            raise ValueError("Expected a thin arm64 executable")
        if command_bytes > len(binary) - 32:
            raise ValueError("Truncated Mach-O load commands")
        position = 32
        device_platform = False
        for _ in range(commands):
            if position + 8 > 32 + command_bytes:
                raise ValueError("Invalid Mach-O command count")
            command, size = struct.unpack_from("<2I", binary, position)
            if size < 8 or position + size > 32 + command_bytes:
                raise ValueError("Invalid Mach-O command length")
            if command == 0x32:
                if size < 24:
                    raise ValueError("Invalid build-version command")
                platform = struct.unpack_from("<I", binary, position + 8)[0]
                if platform != 2:
                    raise ValueError("Executable is not an iOS-device binary")
                device_platform = True
            position += size
        if not device_platform:
            raise ValueError("No iOS-device build-version evidence")
        web = Path(args.web)
        sources = sorted(path for path in web.iterdir() if path.is_file() and path.suffix in (".html", ".css", ".js"))
        if not sources or not (web / "index.html").is_file():
            raise ValueError("Missing bundled web source")
        for source in sources:
            if archive.read(root + "Web/" + source.name) != source.read_bytes():
                raise ValueError("Bundled source differs: " + source.name)
    manifest = {
        "source_commit": args.source_sha,
        "ipa": ipa.name,
        "sha256": hashlib.sha256(ipa.read_bytes()).hexdigest(),
        "bytes": ipa.stat().st_size,
        "bundle_identifier": args.bundle_id,
        "version": args.version,
        "build": args.build,
        "minimum_os": info.get("MinimumOSVersion"),
        "checks": ["ZIP integrity", "bundle metadata", "arm64 executable", "iOS device platform", "bundled source byte equality"],
        "signing": "unsigned",
        "physical_device_testing": "not performed",
        "release_status": "private candidate; signing and documented device/release gates remain",
    }
    Path(args.output).write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("ipa", "app-name", "bundle-id", "version", "build", "minimum-os", "source-sha", "web", "output"):
        parser.add_argument("--" + name, required=True)
    verify(parser.parse_args())
