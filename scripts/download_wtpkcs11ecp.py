#!/usr/bin/env python3
"""Utility for downloading wtpkcs11ecp libraries from the 3rd-party release."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional
import zipfile

API_BASE = "https://api.github.com"
DEFAULT_RELEASE_TAG = "3rdparty"


def make_headers(token: Optional[str], accept: str) -> dict[str, str]:
    headers = {
        "User-Agent": "wallet-tool-build-scripts",
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_release(repo: str, tag: str, token: Optional[str]) -> dict:
    url = f"{API_BASE}/repos/{repo}/releases/tags/{tag}"
    request = urllib.request.Request(url, headers=make_headers(token, "application/vnd.github+json"))
    try:
        with urllib.request.urlopen(request) as response:  # type: ignore[arg-type]
            return json.load(response)
    except urllib.error.HTTPError as exc:  # pragma: no cover - network failures are reported
        message = exc.read().decode("utf-8", errors="ignore")
        raise SystemExit(
            f"Failed to fetch release '{tag}' from repo '{repo}': {exc.code} {exc.reason}\n{message}"
        ) from exc


def find_asset(assets: Iterable[dict], name: Optional[str], patterns: Iterable[str]) -> dict:
    patterns_lc = [p.lower() for p in patterns]

    def matches(asset: dict) -> bool:
        asset_name_lc = asset.get("name", "").lower()
        return all(p in asset_name_lc for p in patterns_lc)

    if name:
        for asset in assets:
            if asset.get("name") == name:
                return asset
        raise SystemExit(f"Asset with exact name '{name}' not found in release")

    candidates = [asset for asset in assets if matches(asset)]
    if not candidates:
        raise SystemExit(
            "No assets matched the specified patterns. "
            "Use --pattern multiple times or --asset-name to select the asset explicitly."
        )
    if len(candidates) > 1:
        asset_names = ", ".join(a.get("name", "<unknown>") for a in candidates)
        raise SystemExit(
            "Multiple assets match the specified patterns: "
            f"{asset_names}. Provide a more specific pattern or --asset-name."
        )
    return candidates[0]


def download_asset(url: str, token: Optional[str], destination: Path) -> None:
    request = urllib.request.Request(url, headers=make_headers(token, "application/octet-stream"))
    with urllib.request.urlopen(request) as response, destination.open("wb") as handle:  # type: ignore[arg-type]
        shutil.copyfileobj(response, handle)


def extract_library_from_zip(zip_path: Path, pattern: str, target: Path) -> Path:
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.namelist()
        pattern_lc = pattern.lower()
        matching = [m for m in members if pattern_lc in Path(m).name.lower()]
        if not matching:
            available = ", ".join(members)
            raise SystemExit(
                f"Could not find a file containing '{pattern}' inside the archive. "
                f"Available members: {available}"
            )
        if len(matching) > 1:
            raise SystemExit(
                "Multiple files inside the archive matched the pattern. "
                "Please specify a more precise pattern via --library-pattern."
            )
        member = matching[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as destination:
            shutil.copyfileobj(source, destination)
    return target


def move_or_copy(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def ensure_target(pattern: Optional[str], target: Optional[Path], default_name: str) -> Path:
    if target:
        return target
    if pattern:
        pattern_path = Path(pattern)
        if pattern_path.suffix:
            return Path(pattern_path.name)
        return Path(pattern)
    raise SystemExit("Unable to determine target filename. Provide --target or --library-pattern.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download wtpkcs11ecp from GitHub release")
    parser.add_argument(
        "--repository",
        help="GitHub repository in owner/name format. Defaults to the GITHUB_REPOSITORY env var.",
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_RELEASE_TAG,
        help=f"Release tag to download (default: {DEFAULT_RELEASE_TAG}).",
    )
    parser.add_argument(
        "--asset-name",
        help="Exact asset name to download. Overrides pattern matching.",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Substring that must appear in the asset name. Can be specified multiple times.",
    )
    parser.add_argument(
        "--library-pattern",
        help="Substring used to locate the library file inside the archive.",
    )
    parser.add_argument(
        "--target",
        type=Path,
        help="Destination path for the library (relative paths are resolved against the current directory).",
    )
    args = parser.parse_args()

    repository = args.repository or os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        parser.error("--repository must be provided when GITHUB_REPOSITORY is not set")

    token = os.environ.get("GITHUB_TOKEN")
    release = fetch_release(repository, args.tag, token)

    assets = release.get("assets", [])
    if not assets:
        raise SystemExit(f"Release '{args.tag}' in repo '{repository}' does not contain any assets")

    asset = find_asset(assets, args.asset_name, args.pattern)
    download_url = asset.get("browser_download_url")
    if not download_url:
        raise SystemExit("Selected asset is missing download URL")

    asset_name = asset.get("name", "asset")

    print(f"Downloading asset '{asset_name}' from release '{args.tag}' in repo '{repository}'...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_asset_path = Path(tmpdir) / asset_name
        download_asset(download_url, token, tmp_asset_path)
        suffix = tmp_asset_path.suffix.lower()

        library_pattern = args.library_pattern
        target = ensure_target(library_pattern, args.target, asset_name)
        target = target if target.is_absolute() else Path.cwd() / target

        if suffix == ".zip":
            extracted = extract_library_from_zip(tmp_asset_path, library_pattern or target.name, target)
        else:
            extracted = move_or_copy(tmp_asset_path, target)

    print(f"Library saved to {extracted}")


if __name__ == "__main__":
    main()
