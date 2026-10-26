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


def read_manifest():
    """Returns the complete content of static/vendor/manifest.json."""

    with open(MANIFEST, "r", encoding="utf-8") as f:
        return json.load(f)


def write_manifest(data):
    """Writes static/vendor/manifest.json (via a temporary file, so it is never half written)."""

    tmp = MANIFEST + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, MANIFEST)


def libraries(data):
    """Returns the library entries of the manifest (keys starting with '_' are notes)."""

    return {name: lib for name, lib in data.items() if not name.startswith("_")}


def fetch(url):
    """Downloads a URL and returns its content."""

    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {url}")
            return response.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} for {url}") from e


def latest_version(package):
    """Returns the latest version of an npm package."""

    data = json.loads(fetch(f"{API}/{package}/resolved?specifier=latest"))
    return data.get("version")


def version_key(version):
    """Turns '4.10.2' into (4, 10, 2) for comparing; None if the version is not purely numeric."""

    parts = version.split(".")
    return tuple(int(p) for p in parts) if all(p.isdigit() for p in parts) else None


def is_newer(latest, current):
    """True if latest is a newer version than current."""

    if not latest or latest == current:
        return False
    latest_key, current_key = version_key(latest), version_key(current)
    if latest_key is None or current_key is None:
        return True
    return latest_key > current_key


def is_major_step(latest, current):
    """True if the major version changes (e.g. 4.x -> 5.x)."""

    return latest.split(".")[0] != current.split(".")[0]


def lib_dir(name, lib):
    """Returns the local folder of a library version."""

    return os.path.join(VENDOR_DIR, f"{name}-{lib['version']}")


def css_assets(css_text):
    """Returns relative files referenced by url() in a CSS file."""

    urls = re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", css_text)
    return [u for u in urls if not u.startswith(("data:", "http:", "https:", "/"))]


def download(name, lib):
    """Downloads all files of a library (incl. CSS assets) into its folder."""

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
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"{name}: refusing path outside the package: {rel}")
        done.add(rel)

        try:
            content = fetch(f"{base_url}/{rel}")
        except Exception as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(
                f"{name} {lib['version']}: could not download '{rel}' ({e}). "
                f"The file layout may have changed in this version — check the paths "
                f"in static/vendor/manifest.json."
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
    """Deletes all other versions of a library."""

    keep = os.path.basename(lib_dir(name, lib))
    removed = []
    for entry in os.listdir(VENDOR_DIR):
        path = os.path.join(VENDOR_DIR, entry)
        if entry.startswith(f"{name}-") and entry != keep and os.path.isdir(path):
            shutil.rmtree(path)
            removed.append(entry)
    return removed


def is_complete(name, lib):
    """Returns True if all files of a library are present."""

    target = lib_dir(name, lib)
    return all(os.path.isfile(os.path.join(target, p)) for p in list(lib["files"].values()) + [lib["license"]])


def select(libs, names):
    """Returns the libraries to work on (all, or only the given names)."""

    unknown = [n for n in names if n not in libs]
    if unknown:
        raise SystemExit(f"Unknown library: {', '.join(unknown)} (known: {', '.join(libs)})")
    return {n: libs[n] for n in names} if names else libs


def cmd_check(libs):
    """Shows which libraries have newer versions and which are missing locally."""

    updates = missing = 0
    for name, lib in libs.items():
        local = "" if is_complete(name, lib) else "  [not downloaded]"
        missing += bool(local)
        try:
            latest = latest_version(lib["package"])
        except Exception as e:
            print(f"  {name:16} {lib['version']:10} could not check: {e}{local}")
            continue
        if is_newer(latest, lib["version"]):
            updates += 1
            note = "  (major version, needs --major)" if is_major_step(latest, lib["version"]) else ""
            print(f"  {name:16} {lib['version']:10} -> {latest} available{note}{local}")
        else:
            print(f"  {name:16} {lib['version']:10} up to date{local}")

    if updates or missing:
        print("\nRun: python3 update_vendor.py --update")
        print("Major versions are skipped unless --major is given; check their changelog first.")


def cmd_update(data, names, allow_major):
    """Raises versions in the manifest to the latest release, downloads them and removes old versions."""

    errors = 0
    for name, lib in select(libraries(data), names).items():
        current = lib["version"]
        try:
            latest = latest_version(lib["package"])
        except Exception as e:
            print(f"  {name:16} {current:10} could not check for updates: {e}")
            latest = None

        target = current
        if is_newer(latest, current):
            if is_major_step(latest, current) and not allow_major:
                print(f"  {name:16} {current:10} -> {latest} skipped (major version, use --major)")
            else:
                target = latest

        try:
            if target != current:
                new_lib = {**lib, "version": target}
                count = download(name, new_lib)
                data[name]["version"] = target
                write_manifest(data)
                lib = new_lib
                print(f"  {name:16} {current:10} -> {target} updated ({count} files, manifest.json changed)")
            elif not is_complete(name, lib):
                count = download(name, lib)
                print(f"  {name:16} {current:10} downloaded ({count} files)")
            else:
                print(f"  {name:16} {current:10} up to date")
        except Exception as e:
            errors += 1
            print(f"  {name:16} {current:10} FAILED: {e}")
            print(f"  {'':16} {'':10} manifest.json still points to {current}")
            continue

        for old in remove_old_versions(name, lib):
            print(f"  {name:16} removed old version {old}")

    print("\nDone. Restart NetPAC (sudo systemctl restart netpac-web), test it, then commit static/vendor/.")
    return errors


def main():
    """Command line entry point: check (default) or --update."""

    parser = argparse.ArgumentParser(
        description="Manage NetPAC's local frontend libraries. Without options, only checks for updates.")
    parser.add_argument("--update", action="store_true",
                        help="raise the versions in manifest.json to the latest release and download them")
    parser.add_argument("--major", action="store_true",
                        help="with --update: also install new major versions (may break NetPAC)")
    parser.add_argument("libs", nargs="*", metavar="LIB",
                        help="with --update: only these libraries (e.g. chartjs animejs)")
    args = parser.parse_args()

    if (args.major or args.libs) and not args.update:
        parser.error("--major and library names can only be used together with --update")

    data = read_manifest()
    try:
        if args.update:
            sys.exit(1 if cmd_update(data, args.libs, args.major) else 0)
        cmd_check(libraries(data))
    except SystemExit:
        raise
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
