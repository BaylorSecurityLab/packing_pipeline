"""
Dataset Statistics Generator for Packer Corpus YAML
Parses packer_corpus.yaml and generates comprehensive statistics

This script analyzes the packer corpus YAML file and provides detailed statistics about:
- Total number of packers and test cases
- GUI vs CLI breakdown
- Tag distribution
- Architecture support
- License distribution
- Test coverage per packer
- Known issues tracking
- And more...

Usage:
    # Print full statistics
    python dataset_stats.py

    # Print quick summary
    python dataset_stats.py --summary

    # Export to JSON
    python dataset_stats.py --json stats.json

    # Use custom YAML path
    python dataset_stats.py --yaml /path/to/packer_corpus.yaml

Features:
    - Comprehensive statistics reporting
    - Quick summary view
    - JSON export for programmatic access
    - Automatic detection of YAML file location
    - Detailed breakdown of packer characteristics
"""

import sys
import json
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any
import yaml


class DatasetStatistics:
    def __init__(self, yaml_path: str):
        """Initialize with path to packer_corpus.yaml"""
        self.yaml_path = Path(yaml_path)
        if not self.yaml_path.exists():
            raise FileNotFoundError(f"YAML file not found: {yaml_path}")

        self.data = self._load_yaml()
        self.definitions = self.data.get('definitions') or []
        self.test_cases = self.data.get('test_cases') or []

    def _load_yaml(self) -> Dict[str, Any]:
        """Load YAML file"""
        with open(self.yaml_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def get_total_packers(self) -> int:
        """Count unique packer definitions"""
        return len(self.definitions)

    def get_total_tests(self) -> int:
        """Count total test cases"""
        return len(self.test_cases)

    def get_gui_count(self) -> Dict[str, int]:
        """Count GUI packers and tests"""
        gui_packers = sum(1 for p in self.definitions if 'GUI' in (p.get('tags') or []))
        gui_tests = sum(1 for t in self.test_cases if 'GUI' in (t.get('tags') or []))
        return {'packers': gui_packers, 'tests': gui_tests}

    def get_cli_count(self) -> Dict[str, int]:
        """Count CLI packers and tests"""
        cli_packers = sum(1 for p in self.definitions if 'CLI' in (p.get('tags') or []))
        cli_tests = sum(1 for t in self.test_cases if 'CLI' in (t.get('tags') or []))
        return {'packers': cli_packers, 'tests': cli_tests}

    def get_tag_distribution(self) -> Counter:
        """Get distribution of all tags"""
        all_tags = []
        for definition in self.definitions:
            all_tags.extend(definition.get('tags') or [])
        return Counter(all_tags)

    def get_tests_per_packer(self) -> Dict[str, int]:
        """Count number of tests per packer"""
        tests_per_packer = Counter()
        for test in self.test_cases:
            packer_name = test.get('packer_name')
            if packer_name:
                tests_per_packer[packer_name] += 1
        return dict(tests_per_packer)

    def get_architecture_distribution(self) -> Counter:
        """Get distribution of architectures"""
        arch_counter = Counter()
        for definition in self.definitions:
            arch = definition.get('arch_origin')
            if arch:
                arch_counter[arch] += 1
        return arch_counter

    def get_output_behavior_distribution(self) -> Counter:
        """Get distribution of output behaviors"""
        output_behaviors = Counter()
        for definition in self.definitions:
            behavior = definition.get('output_behavior')
            if behavior:
                output_behaviors[behavior] += 1
        return output_behaviors

    def get_packers_with_dependencies(self) -> List[str]:
        """Get list of packers that have dependencies"""
        packers_with_deps = []
        for definition in self.definitions:
            deps = definition.get('dependencies', [])
            if deps and deps != []:
                packers_with_deps.append({
                    'packer': definition.get('packer_name'),
                    'dependencies': deps
                })
        return packers_with_deps

    def get_packers_with_known_issues(self) -> List[str]:
        """Get list of packers with known issues"""
        packers_with_issues = []
        for definition in self.definitions:
            issues = definition.get('known_issues') or []
            # Filter out empty strings (and tolerate a null known_issues: key)
            issues = [i for i in issues if i and i.strip()]
            if issues:
                packers_with_issues.append({
                    'packer': definition.get('packer_name'),
                    'issue_count': len(issues)
                })
        return packers_with_issues

    def get_license_distribution(self) -> Counter:
        """Get distribution of licenses"""
        licenses = Counter()
        for definition in self.definitions:
            license_type = definition.get('license')
            if license_type:
                licenses[license_type] += 1
        return licenses

    def get_supported_input_arch_distribution(self) -> Counter:
        """Get distribution of supported input architectures"""
        arch_counter = Counter()
        for definition in self.definitions:
            supported_arch = definition.get('supported_input_arch')
            if isinstance(supported_arch, list):
                for arch in supported_arch:
                    arch_counter[arch] += 1
            elif supported_arch:
                arch_counter[supported_arch] += 1
        return arch_counter

    def print_statistics(self):
        """Print all statistics in a formatted manner"""
        print("=" * 80)
        print("PACKER CORPUS DATASET STATISTICS")
        print("=" * 80)
        print()

        # Basic counts
        print("BASIC COUNTS")
        print("-" * 80)
        print(f"Total Packers:        {self.get_total_packers()}")
        print(f"Total Test Cases:     {self.get_total_tests()}")
        print()

        # GUI vs CLI breakdown
        print("INTERFACE TYPE BREAKDOWN")
        print("-" * 80)
        gui_count = self.get_gui_count()
        cli_count = self.get_cli_count()
        print(f"GUI Packers:          {gui_count['packers']}")
        print(f"GUI Test Cases:       {gui_count['tests']}")
        print(f"CLI Packers:          {cli_count['packers']}")
        print(f"CLI Test Cases:       {cli_count['tests']}")
        print()

        # Tag distribution
        print("TAG DISTRIBUTION")
        print("-" * 80)
        tag_dist = self.get_tag_distribution()
        for tag, count in tag_dist.most_common():
            print(f"{tag:25s} : {count:3d} packers")
        print()

        # Architecture distribution
        print("ARCHITECTURE DISTRIBUTION (Origin)")
        print("-" * 80)
        arch_dist = self.get_architecture_distribution()
        for arch, count in arch_dist.most_common():
            print(f"{arch:10s} : {count:3d} packers")
        print()

        # Supported input architectures
        print("SUPPORTED INPUT ARCHITECTURES")
        print("-" * 80)
        input_arch_dist = self.get_supported_input_arch_distribution()
        for arch, count in input_arch_dist.most_common():
            print(f"{arch:10s} : {count:3d} packers")
        print()

        # Output behavior distribution
        print("OUTPUT BEHAVIOR DISTRIBUTION")
        print("-" * 80)
        output_dist = self.get_output_behavior_distribution()
        for behavior, count in output_dist.most_common():
            print(f"{behavior:20s} : {count:3d} packers")
        print()

        # License distribution
        print("LICENSE DISTRIBUTION")
        print("-" * 80)
        license_dist = self.get_license_distribution()
        for license_type, count in license_dist.most_common():
            print(f"{license_type:30s} : {count:3d} packers")
        print()

        # Tests per packer
        print("TESTS PER PACKER")
        print("-" * 80)
        tests_per_packer = self.get_tests_per_packer()
        total_tests = sum(tests_per_packer.values())
        avg_tests = total_tests / len(tests_per_packer) if tests_per_packer else 0
        print(f"Average tests per packer: {avg_tests:.2f}")
        print()
        for packer, count in sorted(tests_per_packer.items(), key=lambda x: x[1], reverse=True):
            print(f"{packer:25s} : {count:3d} tests")
        print()

        # Packers with dependencies
        print("PACKERS WITH DEPENDENCIES")
        print("-" * 80)
        packers_with_deps = self.get_packers_with_dependencies()
        if packers_with_deps:
            for item in packers_with_deps:
                deps_str = ', '.join(item['dependencies'])
                print(f"{item['packer']:25s} : {deps_str}")
        else:
            print("None")
        print()

        # Packers with known issues
        print("PACKERS WITH KNOWN ISSUES")
        print("-" * 80)
        packers_with_issues = self.get_packers_with_known_issues()
        if packers_with_issues:
            for item in packers_with_issues:
                print(f"{item['packer']:25s} : {item['issue_count']} issue(s)")
            print(f"\nTotal: {len(packers_with_issues)} packers have documented issues")
        else:
            print("None")
        print()

        # Metadata
        print("METADATA")
        print("-" * 80)
        print(f"Version:              {self.data.get('version', 'N/A')}")
        print(f"Maintainer:           {self.data.get('maintainer', 'N/A')}")
        print(f"Last Updated:         {self.data.get('last_updated', 'N/A')}")
        print()

        print("=" * 80)

    def get_summary_dict(self) -> Dict[str, Any]:
        """Get all statistics as a dictionary (useful for JSON export)"""
        gui_count = self.get_gui_count()
        cli_count = self.get_cli_count()

        return {
            'metadata': {
                'version': self.data.get('version', 'N/A'),
                'maintainer': self.data.get('maintainer', 'N/A'),
                'last_updated': self.data.get('last_updated', 'N/A')
            },
            'basic_counts': {
                'total_packers': self.get_total_packers(),
                'total_test_cases': self.get_total_tests()
            },
            'interface_types': {
                'gui': gui_count,
                'cli': cli_count
            },
            'tag_distribution': dict(self.get_tag_distribution()),
            'architecture_distribution': dict(self.get_architecture_distribution()),
            'supported_input_architectures': dict(self.get_supported_input_arch_distribution()),
            'output_behavior_distribution': dict(self.get_output_behavior_distribution()),
            'license_distribution': dict(self.get_license_distribution()),
            'tests_per_packer': self.get_tests_per_packer(),
            'packers_with_dependencies': self.get_packers_with_dependencies(),
            'packers_with_known_issues': self.get_packers_with_known_issues()
        }

    def export_to_json(self, output_path: str):
        """Export statistics to JSON file"""
        stats_dict = self.get_summary_dict()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(stats_dict, f, indent=2, ensure_ascii=False)
        print(f"Statistics exported to: {output_path}")

    def print_quick_summary(self):
        """Print a quick summary of key statistics"""
        gui_count = self.get_gui_count()
        cli_count = self.get_cli_count()

        print("=" * 60)
        print("QUICK SUMMARY - Packer Corpus Dataset")
        print("=" * 60)
        print(f"Total Packers:     {self.get_total_packers()}")
        print(f"Total Tests:       {self.get_total_tests()}")
        print(f"GUI Packers:       {gui_count['packers']}")
        print(f"CLI Packers:       {cli_count['packers']}")
        print(f"GUI Tests:         {gui_count['tests']}")
        print(f"CLI Tests:         {cli_count['tests']}")

        tests_per_packer = self.get_tests_per_packer()
        if tests_per_packer:
            avg_tests = sum(tests_per_packer.values()) / len(tests_per_packer)
            print(f"Avg Tests/Packer:  {avg_tests:.2f}")

        packers_with_issues = self.get_packers_with_known_issues()
        print(f"Packers w/ Issues: {len(packers_with_issues)}")
        print("=" * 60)


def main():
    import argparse

    # Default path relative to the script location
    script_dir = Path(__file__).parent
    default_yaml_path = script_dir.parent / "manifest" / "packer_corpus.yaml"

    parser = argparse.ArgumentParser(
        description="Generate statistics from packer_corpus.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Print full statistics
  python dataset_stats.py

  # Print quick summary
  python dataset_stats.py --summary

  # Export to JSON
  python dataset_stats.py --json stats.json

  # Use custom YAML path
  python dataset_stats.py --yaml /path/to/packer_corpus.yaml
        """
    )

    parser.add_argument(
        '--yaml',
        type=str,
        default=str(default_yaml_path),
        help='Path to packer_corpus.yaml (default: ../manifest/packer_corpus.yaml)'
    )

    parser.add_argument(
        '--json',
        type=str,
        metavar='OUTPUT',
        help='Export statistics to JSON file'
    )

    parser.add_argument(
        '--summary',
        action='store_true',
        help='Print quick summary instead of full statistics'
    )

    args = parser.parse_args()

    try:
        stats = DatasetStatistics(args.yaml)

        if args.json:
            stats.export_to_json(args.json)
        elif args.summary:
            stats.print_quick_summary()
        else:
            stats.print_statistics()

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing YAML: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
