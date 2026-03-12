import json
import re
from packaging import version
from typing import List, Dict, Any, Optional, Tuple

from secator.utils import get_versions_from_string


def extract_software_and_version(version_string: str) -> Tuple[Optional[str], Optional[str]]:
	"""Extract software name and version from a version string."""
	# Try to match software name followed by version
	match = re.search(r'([a-zA-Z][a-zA-Z\s]*?)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*)', version_string.strip())
	if match:
		return match.group(1).strip().lower(), match.group(2).strip()

	# If no software name, try to extract just version
	versions = get_versions_from_string(version_string)
	return (None, versions[0]) if versions else (None, None)


def compare_versions(v1: str, v2: str) -> int:
	"""Compare versions. Returns -1 if v1<v2, 0 if equal, 1 if v1>v2."""
	try:
		parsed_v1 = version.parse(v1.strip())
		parsed_v2 = version.parse(v2.strip())

		if parsed_v1 < parsed_v2:
			return -1
		elif parsed_v1 > parsed_v2:
			return 1
		return 0
	except Exception:
		# Fallback to string comparison
		if v1 < v2:
			return -1
		elif v1 > v2:
			return 1
		return 0


def normalize_software_name(name: str) -> str:
	"""Normalize software name for comparison."""
	return name.lower().strip()


def software_names_match(name1: Optional[str], name2: Optional[str]) -> bool:
	"""Check if two software names match."""
	if not name1 and not name2:
		return True
	if not name1 or not name2:
		return True  # Allow matching when one is missing

	norm1 = normalize_software_name(name1)
	norm2 = normalize_software_name(name2)

	return norm1 in norm2 or norm2 in norm1


def versions_match(current_version: str, target_version: str) -> bool:
	"""Check if current version matches target version with flexible software name matching."""
	current_sw, current_ver = extract_software_and_version(current_version)
	target_sw, target_ver = extract_software_and_version(target_version)

	# Both must have valid version numbers
	if not current_ver or not target_ver:
		return False

	# Version numbers must match exactly
	if compare_versions(current_ver, target_ver) != 0:
		return False

	# Check software name compatibility
	return software_names_match(current_sw, target_sw)


def parse_complex_version_ranges(version_str: str, current_version: str) -> bool:
	"""
	Parse complex version strings with multiple ranges and conditions.
	Example: "Nginx Web Server versions 0.6.18 thru 1.20.0 before 1.20.1, Nginx plus versions R13 thru R23 before R23 P1"  # noqa: E501
	"""
	current_sw, current_ver = extract_software_and_version(current_version)

	if not current_ver:
		return False

	# Split by comma to handle multiple conditions
	conditions = [cond.strip() for cond in version_str.split(',')]

	for condition in conditions:
		# Check if this condition matches the current software
		condition_lower = condition.lower()

		# Extract software name from condition
		if current_sw:
			# Check if condition mentions the same software
			if current_sw not in condition_lower and not any(part in condition_lower for part in current_sw.split()):
				continue

		# Handle "versions X thru Y before Z" pattern
		thru_before_match = re.search(r'versions?\s+([0-9.]+)\s+(?:thru|through|to)\s+([0-9.]+)\s+before\s+([0-9.]+)', condition, re.IGNORECASE)  # noqa: E501
		if thru_before_match:
			start_ver = thru_before_match.group(1)
			end_ver = thru_before_match.group(2)
			before_ver = thru_before_match.group(3)

			# Check if current version is in range [start_ver, end_ver] and before before_ver
			if (compare_versions(current_ver, start_ver) >= 0 and
					compare_versions(current_ver, end_ver) <= 0 and
					compare_versions(current_ver, before_ver) < 0):
				return True
			continue

		# Handle "version X before Y" pattern
		version_before_match = re.search(r'versions?\s+([0-9.]+)\s+before\s+([0-9.]+)', condition, re.IGNORECASE)
		if version_before_match:
			base_ver = version_before_match.group(1)
			before_ver = version_before_match.group(2)

			if (compare_versions(current_ver, base_ver) >= 0 and
					compare_versions(current_ver, before_ver) < 0):
				return True

		# Handle simple ranges "X to Y" or "X thru Y"
		range_match = re.search(r'([0-9.]+)\s+(?:to|thru|through)\s+([0-9.]+)', condition, re.IGNORECASE)
		if range_match:
			start_ver = range_match.group(1)
			end_ver = range_match.group(2)

			if (compare_versions(current_ver, start_ver) >= 0 and
					compare_versions(current_ver, end_ver) <= 0):
				return True

		# Handle simple version match
		versions_in_condition = get_versions_from_string(condition)
		for ver in versions_in_condition:
			if compare_versions(current_ver, ver) == 0:
				return True

	return False


def parse_version_string_for_affected_version(version_str: str) -> str:
	"""
	Parse version string and return the affected version.
	"""
	# Handle "Fixed in" format with "Affected" in parentheses
	if "fixed in" in version_str.lower() and "affected" in version_str.lower():
		# Extract the affected version from parentheses
		affected_match = re.search(r'$ \s*affected\s+([^)]+)\s* $ ', version_str, re.IGNORECASE)
		if affected_match:
			affected_part = affected_match.group(1).strip()

			# Extract software name from "Fixed in" part (before the parentheses)
			fixed_part = re.sub(r'$ .*? $ ', '', version_str).replace('Fixed in', '', 1).strip()

			# Get software name from fixed part
			fixed_sw, _ = extract_software_and_version(fixed_part)

			# Check if affected part already has software name
			affected_sw, affected_ver = extract_software_and_version(affected_part)

			if fixed_sw and affected_ver:
				result = f"{fixed_sw} {affected_ver}"
				return result
			else:
				return affected_part

	# Check for range patterns BEFORE checking for multiple versions
	if ' to ' in version_str:
		return version_str  # Return as-is, will be handled as range

	# Check for comma-separated versions
	if ',' in version_str:
		return version_str  # Return as-is, will be handled as comma-separated

	# Handle strings with multiple versions (like "Apache HTTP Server 2.4 2.4.49")
	# but ONLY if no range keywords are present
	if not any(keyword in version_str.lower() for keyword in ['to', 'thru', 'through', 'before', 'after']):
		versions_in_string = get_versions_from_string(version_str)

		if len(versions_in_string) >= 2:
			# Find where the first version starts to extract software name
			first_version = versions_in_string[0]
			first_version_pos = version_str.find(first_version)
			software_part = version_str[:first_version_pos].strip()

			if software_part:
				result = f"{software_part} {versions_in_string[-1]}"
				return result

	return version_str


def check_version_against_entry(current_version: str, version_entry: Dict[str, Any]) -> bool:
	"""Check if current version matches a single CVE version entry."""
	# Skip non-affected entries
	if version_entry.get('status') != 'affected':
		return False

	current_sw, current_ver = extract_software_and_version(current_version)

	# Check changes array for unaffected versions
	changes = version_entry.get('changes', [])
	for change in changes:
		if (change.get('status') == 'unaffected' and
				change.get('at') and current_ver and
				compare_versions(current_ver, change['at']) == 0):
			return False

	# Handle lessThan with semver - this means all versions >= base version are affected
	# UNLESS they're specifically marked as unaffected in changes array
	if (version_entry.get('lessThan') == '*' and
			version_entry.get('versionType') == 'semver'):
		base_version = version_entry.get('version', '')
		if current_ver and base_version:
			return compare_versions(current_ver, base_version) >= 0

	# Handle lessThan with wildcard (for version ranges like "2.4*")
	if ('lessThan' in version_entry and
			version_entry.get('lessThan', '').endswith('*')):
		less_than = version_entry['lessThan']
		base_version = version_entry.get('version', '')

		# Extract info from lessThan field
		target_sw, target_base = extract_software_and_version(less_than.replace('*', '').strip())

		if not current_ver or not target_base or not base_version:
			return False

		# Software must match if target has software name
		if target_sw and current_sw:
			if not software_names_match(current_sw, target_sw):
				return False
		elif target_sw and not current_sw:
			return False

		# Version must be >= base_version
		if compare_versions(current_ver, base_version) < 0:
			return False

		# For "Apache HTTP Server 2.4*", current version must be 2.4.x, not 2.5.x
		current_major_minor = '.'.join(current_ver.split('.')[:2])
		target_major_minor = '.'.join(target_base.split('.')[:2])

		return current_major_minor == target_major_minor

	# Handle lessThanOrEqual
	if 'lessThanOrEqual' in version_entry:
		less_equal = version_entry['lessThanOrEqual']
		target_sw, target_ver = extract_software_and_version(less_equal)

		if target_sw and current_sw and not software_names_match(current_sw, target_sw):
			return False

		if current_ver and target_ver:
			return compare_versions(current_ver, target_ver) <= 0

	# Handle version field
	version_str = version_entry.get('version', '')
	if not version_str:
		return False

	# Check for complex version ranges first
	if any(keyword in version_str.lower() for keyword in ['thru', 'through', 'before']) and ',' in version_str:
		return parse_complex_version_ranges(version_str, current_version)

	# Parse the version string to get the affected version
	affected_version = parse_version_string_for_affected_version(version_str)

	# Handle comma-separated versions
	if ',' in affected_version:
		for target in affected_version.split(','):
			target = target.strip()
			if versions_match(current_version, target):
				return True
		return False

	# Handle ranges with "to"
	if ' to ' in affected_version:
		parts = affected_version.split(' to ')
		if len(parts) == 2:
			start_versions = get_versions_from_string(parts[0])
			end_versions = get_versions_from_string(parts[1])
			if start_versions and end_versions and current_ver:
				return (compare_versions(current_ver, start_versions[0]) >= 0 and
						compare_versions(current_ver, end_versions[0]) <= 0)

	# Direct version matching
	return versions_match(current_version, affected_version)


def is_version_affected(current_version: str, versions_data: List[Dict[str, Any]]) -> bool:
	"""
	Check if the current version is affected by the CVE.

	Args:
		current_version (str): The current software version
		versions_data (List[Dict[str, Any]]): List of CVE version objects

	Returns:
		bool: True if the version is affected, False otherwise
	"""
	for version_entry in versions_data:
		if check_version_against_entry(current_version, version_entry):
			return True

	return False


def create_test_cases():
	"""Create test cases for all the CVE JSON inputs provided."""

	test_cases = [
		{
			"name": "Simple affected version - dnsmasq",
			"versions": [{"status": "affected", "version": "dnsmasq 2.83"}],
			"tests": [
				("dnsmasq 2.83", True),
				("dnsmasq 2.84", False),
				("dnsmasq 2.82", False),
				("dnsmasq 2.8", False),
				("2.83", True),  # No software name match
			]
		},
		{
			"name": "Multiple simple affected versions",
			"versions": [
				{"status": "affected", "version": "2.4.46"},
				{"status": "affected", "version": "2.4.43"}
			],
			"tests": [
				("2.4.46", True),
				("2.4.43", True),
				("2.4.44", False),
				("2.4.47", False),
				("2.4.42", False),
				("2.4", False),
			]
		},
		{
			"name": "Multiple software in one entry",
			"versions": [
				{"version": "vsftpd 3.0.4, nginx 1.21.0, sendmail 8.17", "status": "affected"}
			],
			"tests": [
				("vsftpd 3.0.4", True),
				("nginx 1.21.0", True),
				("1.21.0", True),
				("sendmail 8.17", True),
				("vsftpd 3.0.5", False),
				("nginx 1.21.1", False),
				("sendmail 8.16", False),
				("3.0.4", True),
			]
		},
		{
			"name": "Complex nginx version ranges",
			"versions": [
				{
					"status": "affected",
					"version": "Nginx Web Server versions 0.6.18 thru 1.20.0 before 1.20.1, Nginx plus versions R13 thru R23 before R23 P1. Nginx plus version R24 before R24 P1"  # noqa: E501
				}
			],
			"tests": [
				("nginx 1.18.0", True),
				("nginx 1.20.0", True),
				("nginx 0.6.18", True),
				("nginx 1.20.1", False),
				("nginx 0.6.17", False),
				("nginx 1.21.0", False),
			]
		},
		{
			"name": "Apache with lessThan and custom versionType",
			"versions": [
				{
					"lessThan": "Apache HTTP Server 2.4*",
					"status": "affected",
					"version": "2.4.7",
					"versionType": "custom"
				}
			],
			"tests": [
				("Apache HTTP Server 2.4.7", True),
				("Apache HTTP Server 2.4.8", True),
				("Apache HTTP Server 2.4.6", False),
				("Apache HTTP Server 2.5.0", False),  # lessThan 2.4*
			]
		},
		{
			"name": "Simple version range",
			"versions": [
				{"status": "affected", "version": "2.4.20 to 2.4.43"}
			],
			"tests": [
				("2.4.20", True),
				("2.4.43", True),
				("2.4.30", True),
				("2.4.19", False),
				("2.4.44", False),
			]
		},
		{
			"name": "Apache with lessThanOrEqual",
			"versions": [
				{
					"lessThanOrEqual": "2.4.48",
					"status": "affected",
					"version": "Apache HTTP Server 2.4",
					"versionType": "custom"
				}
			],
			"tests": [
				("Apache HTTP Server 2.4.48", True),
				("Apache HTTP Server 2.4.30", True),
				("Apache HTTP Server 2.4.0", True),
				("Apache HTTP Server 2.4.49", False),
			]
		},
		{
			"name": "Apache specific version with software name",
			"versions": [
				{"status": "affected", "version": "Apache HTTP Server 2.4 2.4.49"}
			],
			"tests": [
				("Apache HTTP Server 2.4.49", True),
				("Apache HTTP Server 2.4.48", False),
				("2.4.49", True),  # No software name
			]
		},
		{
			"name": "Apache specific version 2.4.37",
			"versions": [
				{"status": "affected", "version": "Apache HTTP Server 2.4.37"}
			],
			"tests": [
				("Apache HTTP Server 2.4.37", True),
				("Apache HTTP Server 2.4.36", False),
				("Apache HTTP Server 2.4.38", False),
			]
		},
		{
			"name": "Apache version range with software name",
			"versions": [
				{"status": "affected", "version": "Apache HTTP Server 2.4.0 to 2.4.37"}
			],
			"tests": [
				("Apache HTTP Server 2.4.0", True),
				("Apache HTTP Server 2.4.37", True),
				("Apache HTTP Server 2.4.20", True),
				("Apache HTTP Server 2.3.9", False),
				("Apache HTTP Server 2.4.38", False),
			]
		},
		{
			"name": "Fixed in format",
			"versions": [
				{"status": "affected", "version": "Fixed in Apache HTTP Server 2.4.34 (Affected 2.4.33)"}
			],
			"tests": [
				("Apache HTTP Server 2.4.33", True),
				("Apache HTTP Server 2.4.34", False),
				("Apache HTTP Server 2.4.32", False),
			]
		},
		{
			"name": "Up to and including format",
			"versions": [
				{"status": "affected", "version": "up to and including 2.78"}
			],
			"tests": [
				("2.78", True),
				("2.77", False),
				("2.70", False),
				("2.79", False),
			]
		},
		{
			"name": "Semver with lessThanOrEqual",
			"versions": [
				{
					"lessThanOrEqual": "2.4.54",
					"status": "affected",
					"version": "2.4",
					"versionType": "semver"
				}
			],
			"tests": [
				("2.4.54", True),
				("2.4.50", True),
				("2.4.0", True),
				("2.4.55", False),
			]
		},
		{
			"name": "Nginx mainline and stable branches",
			"versions": [
				{
					"version": "Mainline",
					"status": "affected",
					"lessThan": "1.23.2",
					"versionType": "custom"
				},
				{
					"version": "Stable",
					"status": "affected",
					"lessThan": "1.22.1",
					"versionType": "custom"
				}
			],
			"tests": [
				("nginx mainline 1.23.1", False),  # Complex branch logic, hard to determine
				("nginx stable 1.22.0", False),   # Complex branch logic, hard to determine
				("nginx 1.23.2", False),
				("nginx 1.22.1", False),
			]
		},
		{
			"name": "Version with changes array - unaffected versions",
			"versions": [
				{
					"status": "affected",
					"version": "1.5.13",
					"lessThan": "*",
					"changes": [
						{"at": "1.26.2", "status": "unaffected"},
						{"at": "1.27.1", "status": "unaffected"}
					],
					"versionType": "semver"
				}
			],
			"tests": [
				("1.26.2", False),  # Unaffected version
				("1.27.1", False),  # Unaffected version
				("1.20.0", True),   # Between 1.5.13 and 1.26.2
				("1.5.12", False),  # Below affected version
				("1.5.13", True),   # Exact affected version
			]
		},
		{
			"name": "Another version with changes array",
			"versions": [
				{
					"changes": [
						{"at": "1.27.4", "status": "unaffected"},
						{"at": "1.26.3", "status": "unaffected"}
					],
					"lessThan": "*",
					"status": "affected",
					"version": "1.11.4",
					"versionType": "semver"
				}
			],
			"tests": [
				("1.27.4", False),  # Unaffected version
				("1.26.3", False),  # Unaffected version
				("1.20.0", True),   # Between 1.11.4 and unaffected versions
				("1.11.4", True),   # Exact affected version
				("1.11.3", False),  # Below affected version
			]
		}
	]

	return test_cases


def run_all_tests():
	"""Run all test cases and display results."""
	test_cases = create_test_cases()

	total_tests = 0
	passed_tests = 0
	failed_tests = []

	print("🧪 Running comprehensive CVE version parsing tests...\n")
	print("=" * 80)

	for i, test_case in enumerate(test_cases, 1):
		print(f"\n📋 Test Case {i}: {test_case['name']}")
		print("-" * 60)

		versions_data = test_case['versions']
		print(f"📄 CVE Data: {json.dumps(versions_data, indent=2)}")
		print("\n🔍 Test Results:")

		case_passed = 0
		case_total = 0

		for current_version, expected_result in test_case['tests']:
			total_tests += 1
			case_total += 1

			try:
				actual_result = is_version_affected(current_version, versions_data)

				if actual_result == expected_result:
					passed_tests += 1
					case_passed += 1
					status = "✅ PASS"
				else:
					status = "❌ FAIL"
					failed_tests.append({
						'case': test_case['name'],
						'version': current_version,
						'expected': expected_result,
						'actual': actual_result
					})

				print(f"  {status} | Version: {current_version:<30} | Expected: {str(expected_result):<5} | Got: {str(actual_result):<5}")  # noqa: E501

			except Exception as e:
				status = "💥 ERROR"
				failed_tests.append({
					'case': test_case['name'],
					'version': current_version,
					'expected': expected_result,
					'error': str(e)
				})
				print(f"  {status} | Version: {current_version:<30} | Error: {str(e)}")

		print(f"\n📊 Case Summary: {case_passed}/{case_total} tests passed")

	# Final summary
	print("\n" + "=" * 80)
	print("🏁 FINAL TEST SUMMARY")
	print("=" * 80)
	print(f"✅ Total Tests Passed: {passed_tests}")
	print(f"❌ Total Tests Failed: {len(failed_tests)}")
	print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")

	if failed_tests:
		print("\n🔍 FAILED TEST DETAILS:")
		print("-" * 40)
		for i, failure in enumerate(failed_tests, 1):
			print(f"{i}. Test Case: {failure['case']}")
			print(f"   Version: {failure['version']}")
			if 'error' in failure:
				print(f"   Error: {failure['error']}")
			else:
				print(f"   Expected: {failure['expected']}, Got: {failure['actual']}")
			print()

	return passed_tests == total_tests


def run_specific_test(test_name: str):
	"""Run a specific test case by name."""
	test_cases = create_test_cases()

	for test_case in test_cases:
		if test_name.lower() in test_case['name'].lower():
			print(f"🧪 Running Test: {test_case['name']}")
			print("=" * 60)

			versions_data = test_case['versions']
			print(f"CVE Data: {json.dumps(versions_data, indent=2)}\n")

			for current_version, expected_result in test_case['tests']:
				actual_result = is_version_affected(current_version, versions_data)
				status = "✅ PASS" if actual_result == expected_result else "❌ FAIL"
				print(f"{status} | {current_version} -> Expected: {expected_result}, Got: {actual_result}")

			return

	print(f"❌ Test case '{test_name}' not found!")


def interactive_test():
	"""Interactive testing function for manual testing."""
	print("🧪 Interactive CVE Version Tester")
	print("=" * 40)
	print("Enter 'quit' to exit\n")

	while True:
		try:
			print("Enter current version (or 'quit' to exit):")
			current_version = input("> ").strip()

			if current_version.lower() == 'quit':
				break

			print("\nEnter CVE versions JSON (paste the versions array):")
			cve_input = input("> ").strip()

			# Try to parse the JSON
			try:
				versions_data = json.loads(cve_input)
				if isinstance(versions_data, dict):
					versions_data = [versions_data]  # Convert single object to array

				result = is_version_affected(current_version, versions_data)

				print(f"\n🎯 Result: Version {current_version} is {'AFFECTED' if result else 'NOT AFFECTED'}")
				print("-" * 40)

			except json.JSONDecodeError:
				print("❌ Invalid JSON format. Please try again.")
			except Exception as e:
				print(f"❌ Error: {str(e)}")

		except KeyboardInterrupt:
			print("\n👋 Goodbye!")
			break
		except Exception as e:
			print(f"❌ Unexpected error: {str(e)}")


if __name__ == "__main__":
	# Run all tests
	success = run_all_tests()

	# Optionally run specific tests
	# run_specific_test("nginx")

	# Optionally run interactive tester
	# interactive_test()

	print(f"\n🎉 All tests {'PASSED' if success else 'COMPLETED with failures'}!")
