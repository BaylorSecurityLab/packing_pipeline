import subprocess
import os
import requests
import time
import json
import glob
import zipfile
import shutil

# --- CONFIGURATION ---
LIMIT = 100
BASE_DIR = "../benign_sources"
MANIFEST_DIR = os.path.join(BASE_DIR, "manifest")

# File mappings (Removed x64)
FILES = {
    "x86": "x86.json",
    "processed_ids": "processed_ids.json"
}


def load_manifest():
    """Loads the x86 and processed_ids JSON files."""
    data = {"x86": [], "processed_ids": []}

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
    """Saves the data into separate JSON files inside MANIFEST_DIR."""
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
    """Removes leftover winget YAML files."""
    yaml_files = glob.glob(os.path.join(folder, "*.yaml"))
    for f in yaml_files:
        try:
            os.remove(f)
        except OSError:
            pass


def handle_zips(folder):
    """
    Finds .zip files, extracts executables, moves them to the root of 'folder',
    and deletes the zip and other artifacts.
    """
    zip_files = glob.glob(os.path.join(folder, "*.zip"))

    for zip_path in zip_files:
        try:
            print(f"   -> Unzipping: {os.path.basename(zip_path)}")
            # Create a temporary extraction folder
            temp_extract_dir = os.path.join(folder, "temp_extract_zone")
            os.makedirs(temp_extract_dir, exist_ok=True)

            # Extract everything
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_extract_dir)

            # Walk through the temp folder to find .exe or .msi
            found_exe = False
            for root, dirs, files in os.walk(temp_extract_dir):
                for file in files:
                    if file.lower().endswith(('.exe', '.msi')):
                        source = os.path.join(root, file)
                        dest = os.path.join(folder, file)

                        # Move the executable out to the main folder
                        if not os.path.exists(dest):
                            shutil.move(source, dest)
                            found_exe = True
                            print(f"   -> Extracted: {file}")

            # Cleanup: Delete the zip and the temp folder
            os.remove(zip_path)
            shutil.rmtree(temp_extract_dir)

            if not found_exe:
                print(f"   -> Warning: No .exe/.msi found in {os.path.basename(zip_path)}")

        except Exception as e:
            print(f"   -> Zip Error: {e}")


def download_packages(targets, manifest_data):
    print(f"\nProcessing {len(targets)} new targets into '{BASE_DIR}'...\n")

    # Only create x86 folder
    os.makedirs(os.path.join(BASE_DIR, "x86"), exist_ok=True)

    for index, app_id in enumerate(targets):
        print(f"[{index + 1}/{len(targets)}] Processing: {app_id}")

        # --- PROCESS x86 ONLY ---
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
            handle_zips(os.path.join(BASE_DIR, "x86"))
            print(f"   -> [x86] Success")

        except subprocess.CalledProcessError:
            # If x86 is not available for this package, we skip it silently
            print(f"   -> [x86] Skipped/Failed (Not available or Error)")

        # Always mark as processed so we don't try this ID again
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