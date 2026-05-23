"""
Detector access definitions for the public free edition and optional private tiers.

When PAID_PLANS_ENABLED is false, the scanner allows the full detector set.
"""

# Core detectors available in the baseline free experience
CORE_DETECTORS = [
    'reflection_detector',
    'sql_pattern_detector',
    'xss_pattern_detector',
    'open_redirect_detector',
    'security_headers_detector',
    'dir_listing_detector',
]

# Extended detector set used by private tiers when paid plans are enabled
EXTENDED_DETECTORS = CORE_DETECTORS + [
    'ssrf_detector',
    'advanced_ssrf_detector',
    'csrf_detector',
    'lfi_detector',
    'header_injection_detector',
    'secret_detector',
    'idor_detector',
    'command_injection_detector',
    'xxe_detector',
    'ssti_detector',
]

# Full detector set used by the free public edition and any all-access private tiers
FULL_DETECTOR_SET = EXTENDED_DETECTORS + [
    'ssrf_oob_detector',
    'graphql_detector',
    'jwt_detector',
    'file_upload_detector',
    'subdomain_takeover_detector',
    'cors_detector',
    'oauth_detector',
    'cache_poisoning_detector',
    'prototype_pollution_detector',
    'nosql_injection_detector',
    'api_security_detector',
    'auth_bypass_detector',
    'rate_limit_bypass_detector',
    'brute_force_detector',
    'jwt_vulnerability_scanner',
    'race_condition_detector',
    'graphql_injection_detector',
    'simple_file_list_detector',
    'basic_param_fuzzer',
    'fuzz_detector',
    'injector',
    'api_docs_discovery',
    'js_file_analyzer',
    'backup_file_hunter',
    'old_domain_hunter',
    'github_osint',
    'parameter_fuzzer',
    'cve_database_detector',
    'nuclei_detector',
    'ssrf_oob_advanced_detector',
    'business_logic_detector',
    'subfinder_detector',
    'amass_detector',
    'httpx_detector',
    'katana_detector',
    'gf_pattern_detector',
    'dalfox_detector',
    'ffuf_idor_detector',
    'nmap_detector',
    'apk_analyzer_detector',
    'ios_scanner_detector',
    'interactsh_client',
]

# Detectors that remain verification-gated even in the free edition
VERIFICATION_GATED_DETECTORS = [
    'fuzz_detector',
    'file_upload_detector',
    'brute_force_detector',
    'basic_param_fuzzer',
]