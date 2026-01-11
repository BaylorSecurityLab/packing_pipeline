import tomllib
import subprocess
import datetime
import re
from pathlib import Path

MANIFEST_PATH = Path("../manifest/packer_corpus.yaml")
PYPROJECT_PATH = Path("../pyproject.toml")


def get_git_contributors():
    """Gets unique names of everyone who committed to the repository."""
    try:
        # Run git log to get all author names
        result = subprocess.run(
            ["git", "log", "--format=%an"],
            capture_output=True,
            text=True,
            check=True
        )
        # Sort and deduplicate names
        authors = sorted(list(set(result.stdout.strip().splitlines())))
        return ", ".join(authors)
    except subprocess.CalledProcessError:
        return "Unknown (Git not found)"


def update_manifest_header():
    # 1. Get VERSION from pyproject.toml
    with open(PYPROJECT_PATH, "rb") as f:
        data = tomllib.load(f)
        version = data["project"]["version"]

    # 2. Get MAINTAINERS from Git
    maintainers = get_git_contributors()

    # 3. Get DATE
    today = datetime.date.today().isoformat()

    # 4. Read the existing YAML
    if not MANIFEST_PATH.exists():
        print(f"Error: {MANIFEST_PATH} not found.")
        return

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 5. Regex Replace the specific keys (Surgical update)
    # This preserves your comments and anchors further down the file.

    # Update version
    content = re.sub(
        r'^version:\s*".*?"',
        f'version: "{version}"',
        content,
        flags=re.MULTILINE
    )

    # Update maintainer
    content = re.sub(
        r'^maintainer:\s*".*?"',
        f'maintainer: "{maintainers}"',
        content,
        flags=re.MULTILINE
    )

    # Update last_updated
    content = re.sub(
        r'^last_updated:\s*".*?"',
        f'last_updated: "{today}"',
        content,
        flags=re.MULTILINE
    )

    # 6. Save back
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ Manifest updated: v{version} | {today} | Authors: {maintainers}")


if __name__ == "__main__":
    update_manifest_header()