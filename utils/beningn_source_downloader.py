import subprocess
import os
import requests
import time
import json
import glob
import zipfile
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# --- CONFIGURATION ---
LIMIT = 200
# Max seconds to wait for a single package download before skipping it
DOWNLOAD_TIMEOUT = 60
# Parallel download workers: 80% of available CPU cores (at least 1)
MAX_WORKERS = max(1, int((os.cpu_count() or 1) * 0.80))

# Guards shared manifest state and folder post-processing across threads
_manifest_lock = threading.Lock()
BASE_DIR = "../benign_sources"
MANIFEST_DIR = os.path.join(BASE_DIR, "manifest")

# File mappings (Removed x64)
FILES = {"x86": "x86.json", "processed_ids": "processed_ids.json"}


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


def fetch_new_packages(manifest_data, num_new):
    """Fetches up to `num_new` package IDs that have not been processed yet."""
    processed = manifest_data["processed_ids"]

    if num_new <= 0:
        return []

    new_targets_executables = []
    print(
        f"Sourcing new packages... (Already processed: {len(processed)} | Fetching: {num_new})"
    )

    page = 1
    while len(new_targets_executables) < num_new:
        try:
            url = f"https://api.winget.run/v2/packages?page={page}&take=50"
            res = requests.get(url, timeout=10)
            if res.status_code != 200:
                print(f"API returned status {res.status_code} for {url}")
                break

            data = res.json()
            if not data.get("Packages"):
                break

            for pkg in data["Packages"]:
                p_id = pkg.get("Id")
                if (
                    p_id
                    and (p_id not in processed)
                    and (p_id not in new_targets_executables)
                ):
                    new_targets_executables.append(p_id)
                    if len(new_targets_executables) >= num_new:
                        break
            page += 1
            time.sleep(0.5)
        except Exception as e:
            print(f"API Error on page {page}: {e}")
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
            tqdm.write(f"   -> Unzipping: {os.path.basename(zip_path)}")
            # Create a temporary extraction folder
            temp_extract_dir = os.path.join(folder, "temp_extract_zone")
            os.makedirs(temp_extract_dir, exist_ok=True)

            # Extract everything
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_extract_dir)

            # Walk through the temp folder to find .exe or .msi
            found_exe = False
            for root, dirs, files in os.walk(temp_extract_dir):
                for file in files:
                    if file.lower().endswith((".exe", ".msi")):
                        source = os.path.join(root, file)
                        dest = os.path.join(folder, file)

                        # Move the executable out to the main folder
                        if not os.path.exists(dest):
                            shutil.move(source, dest)
                            found_exe = True
                            tqdm.write(f"   -> Extracted: {file}")

            # Cleanup: Delete the zip and the temp folder
            os.remove(zip_path)
            shutil.rmtree(temp_extract_dir)

            if not found_exe:
                tqdm.write(
                    f"   -> Warning: No .exe/.msi found in {os.path.basename(zip_path)}"
                )

        except Exception as e:
            tqdm.write(f"   -> Zip Error: {e}")


def download_one(app_id, manifest_data):
    """Download a package and keep only its .exe output.

    The package is counted as successful ONLY if it produces at least one
    .exe. Any .msi or other installer artifacts are discarded. Returns True
    on success.
    """
    x86_dir = os.path.join(BASE_DIR, "x86")
    safe_id = app_id.replace("/", "_").replace("\\", "_")
    # Per-package staging dir so parallel downloads never collide and so we
    # can attribute every produced file to this exact package.
    staging = os.path.join(BASE_DIR, "_staging", safe_id)

    success = False
    try:
        shutil.rmtree(staging, ignore_errors=True)
        os.makedirs(staging, exist_ok=True)

        subprocess.run(
            [
                "winget",
                "download",
                "--id",
                app_id,
                "-d",
                staging,
                "-a",
                "x86",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--disable-interactivity",
                "--skip-dependencies",
            ],
            capture_output=True,
            check=True,
            timeout=DOWNLOAD_TIMEOUT,
        )

        # Pull executables out of any zips and drop yaml noise.
        handle_zips(staging)
        delete_yaml_files(staging)

        # Collect every .exe the package produced.
        produced = []
        for root, _dirs, files in os.walk(staging):
            for f in files:
                if f.lower().endswith(".exe") and ".packed" not in f.lower():
                    produced.append(os.path.join(root, f))

        if produced:
            # Move exes into the shared x86 dir + record them under the lock.
            with _manifest_lock:
                for src in produced:
                    name = os.path.basename(src)
                    dest = os.path.join(x86_dir, name)
                    # Disambiguate clashing names so packages don't clobber.
                    if os.path.exists(dest):
                        stem, ext = os.path.splitext(name)
                        name = f"{stem}__{safe_id}{ext}"
                        dest = os.path.join(x86_dir, name)
                    if not os.path.exists(dest):
                        shutil.move(src, dest)
                    if name not in manifest_data["x86"]:
                        manifest_data["x86"].append(name)
            tqdm.write(f"[x86] Success ({len(produced)} exe): {app_id}")
            success = True
        else:
            # No usable executable (e.g. msi-only) -> discard, do not count.
            tqdm.write(f"[x86] No .exe produced, discarded: {app_id}")

    except subprocess.TimeoutExpired:
        # Download took longer than DOWNLOAD_TIMEOUT seconds, skip and move on
        tqdm.write(
            f"[x86] Timed out after {DOWNLOAD_TIMEOUT}s, skipping: {app_id}"
        )

    except subprocess.CalledProcessError:
        # If x86 is not available for this package, we skip it silently
        tqdm.write(f"[x86] Skipped/Failed (Not available or Error): {app_id}")

    finally:
        # Remove the staging dir and any leftover msi/other artifacts.
        shutil.rmtree(staging, ignore_errors=True)

    # Always mark as processed so we don't try this ID again
    with _manifest_lock:
        if app_id not in manifest_data["processed_ids"]:
            manifest_data["processed_ids"].append(app_id)

    return success


def cleanup_msi_and_reconcile(manifest_data):
    """Delete leftover .msi installers and rebuild the x86 list from the
    .exe files actually present on disk, so the count reflects packable exes.
    """
    x86_dir = os.path.join(BASE_DIR, "x86")
    os.makedirs(x86_dir, exist_ok=True)

    removed = 0
    for msi in glob.glob(os.path.join(x86_dir, "*.msi")):
        try:
            os.remove(msi)
            removed += 1
        except OSError:
            pass

    exes = sorted(
        f
        for f in os.listdir(x86_dir)
        if f.lower().endswith(".exe")
        and ".packed" not in f.lower()
        and os.path.isfile(os.path.join(x86_dir, f))
    )
    manifest_data["x86"] = exes
    save_manifest(manifest_data)

    if removed:
        print(f"Cleanup: removed {removed} .msi file(s).")
    print(f"Reconciled x86 list to {len(exes)} .exe file(s) on disk.")


def download_until_limit(manifest_data, target_limit):
    """Keeps fetching and downloading until `target_limit` successful x86 downloads.

    Downloads run in parallel across MAX_WORKERS threads (80% of CPU cores).
    """
    os.makedirs(os.path.join(BASE_DIR, "x86"), exist_ok=True)

    already = len(manifest_data["x86"])
    progress = tqdm(
        total=target_limit, initial=already, desc="Downloaded", unit="pkg"
    )
    print(f"Running with {MAX_WORKERS} parallel workers.")

    attempts = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while len(manifest_data["x86"]) < target_limit:
            needed = target_limit - len(manifest_data["x86"])
            # Over-fetch a bit so workers stay busy even as some IDs fail.
            batch_size = needed + MAX_WORKERS
            targets = fetch_new_packages(manifest_data, batch_size)
            if not targets:
                tqdm.write("No more packages available from source.")
                break

            # Submit the whole batch and process completions as they finish.
            futures = {
                executor.submit(download_one, app_id, manifest_data): app_id
                for app_id in targets
            }

            for future in as_completed(futures):
                if future.result():
                    progress.update(1)
                    progress.set_postfix_str(futures[future])

                attempts += 1
                if attempts % 5 == 0:
                    with _manifest_lock:
                        save_manifest(manifest_data)

                if len(manifest_data["x86"]) >= target_limit:
                    break

    progress.close()
    save_manifest(manifest_data)
    print(f"\nOperation Complete. Total downloaded: {len(manifest_data['x86'])}")


if __name__ == "__main__":
    manifest = load_manifest()
    # Drop stale .msi files and re-base the x86 count on real .exe files.
    cleanup_msi_and_reconcile(manifest)
    already_downloaded = len(manifest["x86"])
    print(
        f"Target total: {LIMIT} | Already downloaded: {already_downloaded} | Remaining: {max(LIMIT - already_downloaded, 0)}"
    )
    if already_downloaded >= LIMIT:
        print("No new packages to process (Limit reached).")
    else:
        download_until_limit(manifest, LIMIT)
