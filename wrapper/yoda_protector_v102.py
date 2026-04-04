"""
Yoda's Protector v1.02 GUI Automation Wrapper
"""

import sys
from pathlib import Path
from yoda_protector_v101_base import YodaProtectorV101Base


class YodaProtectorV102(YodaProtectorV101Base):
    """
    Wrapper for Yoda's Protector v1.02 GUI automation.
    Inherits all UI logic from YodaProtectorV101Base.
    """

    def get_packer_name(self):
        return "yoda_protector_v1.02"


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Yoda's Protector v1.02 GUI Automation Wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--file-path", type=str, default=None, help="Full path to the file to process"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to copy the protected file to",
    )

    args = parser.parse_args()

    script_dir = Path(__file__).parent
    main_dir = script_dir.parent
    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    if not yaml_path.exists():
        print(f"\n[ERROR] YAML file not found at: {yaml_path}")
        return 1

    wrapper = YodaProtectorV102(yaml_path, main_dir)
    success = wrapper.run(file_path=args.file_path, output_dir=args.output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
