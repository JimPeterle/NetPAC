#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
VENDOR_DIR = os.path.join(BASE_DIR, "static", "vendor")
MANIFEST = os.path.join(VENDOR_DIR, "manifest.json")
CDN = "https://cdn.jsdelivr.net/npm"
API = "https://data.jsdelivr.com/v1/packages/npm"


def load_manifest():
    with open(MANIFEST, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {name: lib for name, lib in data.items() if not name.startswith("_")}


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {url}")
            return response.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} for {url}") from e


def latest_version(package):
    data = json.loads(fetch(f"{API}/{package}/resolved?specifier=latest"))
    return data.get("version")


def lib_dir(name, lib):
    return os.path.join(VENDOR_DIR, f"{name}-{lib['version']}")


def css_assets(css_text):
    urls = re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", css_text)
    return [u for u in urls if not u.startswith(("data:", "http:", "https:", "/"))]


def download(name, lib):
    base_url = f"{CDN}/{lib['package']}@{lib['version']}"
    target = lib_dir(name, lib)
    tmp = target + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)

    paths = list(lib["files"].values()) + [lib["license"]]
    queue = list(paths)
    done = set()

    while queue:
        rel = os.path.normpath(queue.pop(0)).replace(os.sep, "/")
        if rel in done:
            continue
        if rel.startswith("../"):
            raise RuntimeError(f"{name}: refusing path outside the package: {rel}")
        done.add(rel)

        try:
            content = fetch(f"{base_url}/{rel}")
        except Exception as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(
                f"{name} {lib['version']}: could not download '{rel}' ({e}). "
                f"The file layout may have changed in this version — check the paths "
                f"in static/vendor/manifest.json, or go back to the previous version."
            ) from e
        dest = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(content)

        if lib.get("css_assets") and rel.endswith(".css"):
            css_dir = os.path.dirname(rel)
            for asset in css_assets(content.decode("utf-8")):
                queue.append(os.path.join(css_dir, asset))

    shutil.rmtree(target, ignore_errors=True)
    os.rename(tmp, target)
    return len(done)


def remove_old_versions(name, lib):
    keep = os.path.basename(lib_dir(name, lib))
    removed = []
    for entry in os.listdir(VENDOR_DIR):
        path = os.path.join(VENDOR_DIR, entry)
        if entry.startswith(f"{name}-") and entry != keep and os.path.isdir(path):
            shutil.rmtree(path)
            removed.append(entry)
    return removed


def is_complete(name, lib):
    target = lib_dir(name, lib)
    return all(os.path.isfile(os.path.join(target, p)) for p in list(lib["files"].values()) + [lib["license"]])


def cmd_check(libs):
    outdated = 0
    for name, lib in libs.items():
        try:
            latest = latest_version(lib["package"])
        except Exception as e:
            print(f"  {name:16} {lib['version']:10} could not check: {e}")
            continue
        if latest and latest != lib["version"]:
            outdated += 1
            major = latest.split(".")[0] != lib["version"].split(".")[0]
            note = "  (major version — may break NetPAC)" if major else ""
            print(f"  {name:16} {lib['version']:10} -> {latest} available{note}")
        else:
            print(f"  {name:16} {lib['version']:10} up to date")
    if outdated:
        print("\nChange the version in static/vendor/manifest.json, then run: python3 update_vendor.py")
        print("Check the library's changelog for breaking changes before updating major versions.")


def cmd_update(libs):
    for name, lib in libs.items():
        if is_complete(name, lib):
            print(f"  {name:16} {lib['version']:10} already present")
        else:
            count = download(name, lib)
            print(f"  {name:16} {lib['version']:10} downloaded ({count} files)")
        for old in remove_old_versions(name, lib):
            print(f"  {name:16} removed old version {old}")
    print("\nDone. Test NetPAC, then commit static/vendor/.")


def main():
    parser = argparse.ArgumentParser(description="Manage NetPAC's local frontend libraries")
    parser.add_argument("--check", action="store_true", help="only show available updates")
    args = parser.parse_args()

    libs = load_manifest()
    try:
        cmd_check(libs) if args.check else cmd_update(libs)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
