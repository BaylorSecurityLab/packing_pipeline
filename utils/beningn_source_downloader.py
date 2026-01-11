import subprocess
import os
import requests
import time
import json
import glob

# --- CONFIGURATION ---
LIMIT = 10
BASE_DIR = "../benign_sources"
MANIFEST_DIR = os.path.join(BASE_DIR, "manifest")

# File mappings
FILES = {
    "x64": "x64.json",
    "x86": "x86.json",
    "processed_ids": "processed_ids.json"
}

def load_manifest():
    """
    Loads the 3 separate JSON files.
    """
    data = {"x64": [], "x86": [], "processed_ids": []}

    for key, filename in FILES.items():
        filepath = os.path.join(MANIFEST_DIR, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    data[key] = json.load(f)
            except json.JSONDecodeError:
                data[key] = []
        else:
            data[key] = []

    return data


def save_manifest(data):
    """Saves the data into 3 separate JSON files inside MANIFEST_DIR."""
    if not os.path.exists(MANIFEST_DIR):
        os.makedirs(MANIFEST_DIR)

    for key, filename in FILES.items():
        filepath = os.path.join(MANIFEST_DIR, filename)
        with open(filepath, "w") as f:
            json.dump(data[key], f, indent=4)


def fetch_new_packages(manifest_data, target_limit):
    processed = manifest_data["processed_ids"]
    current_count = len(processed)

    if current_count >= target_limit:
        return []

    new_targets_executables = []
    print(f"Sourcing new packages... (Current: {current_count} | Target: {target_limit})")

    page = 1
    while (len(new_targets_executables) + current_count) < target_limit:
        try:
            url = f"https://api.winget.run/v2/packages?page={page}&take=50"
            res = requests.get(url, timeout=10)
            if res.status_code != 200: break

            data = res.json()
            if not data.get("Packages"): break

            for pkg in data["Packages"]:
                p_id = pkg.get("Id")
                if p_id and (p_id not in processed) and (p_id not in new_targets_executables):
                    new_targets_executables.append(p_id)
                    if (len(new_targets_executables) + current_count) >= target_limit:
                        break

            page += 1
            time.sleep(0.5)
        except Exception as e:
            print(f"API Error: {e}")
            break

    return new_targets_executables


def delete_yaml_files(folder):
    yaml_files = glob.glob(os.path.join(folder, "*.yaml"))
    for f in yaml_files:
        try:
            os.remove(f)
        except OSError:
            pass


def download_packages(targets, manifest_data):
    print(f"\nProcessing {len(targets)} new targets into '{BASE_DIR}'...\n")

    for arch in ["x64", "x86"]:
        os.makedirs(os.path.join(BASE_DIR, arch), exist_ok=True)

    for index, app_id in enumerate(targets):
        print(f"[{index + 1}/{len(targets)}] Processing: {app_id}")

        try:
            subprocess.run([
                "winget", "download", "--id", app_id,
                "-d", os.path.join(BASE_DIR, "x64"),
                "-a", "x64",
                "--accept-package-agreements", "--accept-source-agreements",
                "--disable-interactivity", "--skip-dependencies"
            ], capture_output=True, check=True)

            if app_id not in manifest_data["x64"]:
                manifest_data["x64"].append(app_id)
            delete_yaml_files(os.path.join(BASE_DIR, "x64"))
            print(f"   -> [x64] Success")
        except subprocess.CalledProcessError:
            pass

        try:
            subprocess.run([
                "winget", "download", "--id", app_id,
                "-d", os.path.join(BASE_DIR, "x86"),
                "-a", "x86",
                "--accept-package-agreements", "--accept-source-agreements",
                "--disable-interactivity", "--skip-dependencies"
            ], capture_output=True, check=True)

            if app_id not in manifest_data["x86"]:
                manifest_data["x86"].append(app_id)
            delete_yaml_files(os.path.join(BASE_DIR, "x86"))
            print(f"   -> [x86] Success")
        except subprocess.CalledProcessError:
            pass

        if app_id not in manifest_data["processed_ids"]:
            manifest_data["processed_ids"].append(app_id)

        if index % 5 == 0:
            save_manifest(manifest_data)

    save_manifest(manifest_data)
    print(f"\nOperation Complete.")


if __name__ == "__main__":
    manifest = load_manifest()
    new_targets = fetch_new_packages(manifest, LIMIT)
    if new_targets:
        download_packages(new_targets, manifest)
    else:
        print("No new packages to process (Limit reached).")