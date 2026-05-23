"""
Detector Categories and Plan-based Access Control
Maps all detectors to categories and defines which plans can access them.
"""

from typing import Optional


def _try_db_plan_context(plan_name: str):
    """Best-effort: use DB-backed categories/detectors when available.

    Returns (categories_out, allowed_detectors_set) or (None, None) on failure.
    """
    try:
        from scans.category_models import ScanCategory, DetectorConfig
    except Exception:
        return None, None

    # If categories exist but detectors have not been populated yet, the DB view would
    # incorrectly report that *no* detectors are allowed. Treat that as "DB not ready".
    try:
        if not DetectorConfig.objects.filter(is_active=True).exists():
            return None, None
    except Exception:
        return None, None

    plan_key = (plan_name or '').lower() or 'free'

    plan_hierarchy = {'free': 0, 'pro': 1, 'enterprise': 2}

    plan_obj = None
    overrides_by_category_id: dict[int, bool] = {}
    try:
        from subscriptions.models import Plan as DbPlan, PlanScanCategoryOverride

        plan_obj = DbPlan.objects.filter(name=plan_key).only('id', 'name', 'allow_dangerous_tools').first()
        if plan_obj is not None:
            overrides_by_category_id = {
                o.category_id: bool(o.is_allowed)
                for o in PlanScanCategoryOverride.objects.filter(plan=plan_obj).only('category_id', 'is_allowed')
            }
    except Exception:
        plan_obj = None
        overrides_by_category_id = {}

    dangerous_ok = bool(getattr(plan_obj, 'allow_dangerous_tools', False)) if plan_obj is not None else (
        plan_hierarchy.get(plan_key, 0) >= plan_hierarchy.get('enterprise', 2)
    )

    def cat_allowed(cat) -> bool:
        try:
            return plan_hierarchy.get(plan_key, 0) >= plan_hierarchy.get(getattr(cat, 'required_plan', 'free'), 0)
        except Exception:
            return False

    categories_out = []
    allowed_detectors: set[str] = set()

    try:
        cats = ScanCategory.objects.filter(is_active=True).order_by('order', 'name')
    except Exception:
        return None, None

    for cat in cats:
        has_access = cat_allowed(cat)
        if cat.id in overrides_by_category_id:
            has_access = overrides_by_category_id[cat.id]
        dets = DetectorConfig.objects.filter(is_active=True, categories=cat).order_by('execution_order', 'name')
        det_list = []
        for det in dets:
            allowed = bool(has_access) and (dangerous_ok or (not det.is_dangerous))
            det_list.append({'name': det.name, 'is_allowed': allowed})
            if allowed:
                allowed_detectors.add(det.name)

        categories_out.append({
            'key': cat.name,
            'name': getattr(cat, 'display_name', cat.name),
            'icon': getattr(cat, 'icon', ''),
            'description': getattr(cat, 'description', ''),
            'required_plan': getattr(cat, 'required_plan', 'free'),
            'is_allowed': bool(has_access),
            'detectors': det_list,
            'detector_count': len(det_list),
        })

    return categories_out, allowed_detectors


# Detector Categories
DETECTOR_CATEGORIES = {
    # WEB SCANNING - Basic web vulnerabilities (All plans)
    'web': {
        'name': 'Web Security',
        'icon': '🌐',
        'description': 'Basic web vulnerability scanning',
        'detectors': [
            'xss_pattern_detector',
            'dalfox_detector',
            'sql_pattern_detector',
            'lfi_detector',
            'open_redirect_detector',
            'xxe_detector',
            'ssti_detector',
            'csrf_detector',
            'cors_detector',
            'security_headers_detector',
            'dir_listing_detector',
            'reflection_detector',
        ],
        'required_plan': 'free',  # Available to all plans
    },

    # INJECTION ATTACKS - Advanced injection testing (Pro+)
    'injection': {
        'name': 'Injection Attacks',
        'icon': '💉',
        'description': 'Advanced SQL, NoSQL, Command injection',
        'detectors': [
            'command_injection_detector',
            'nosql_injection_detector',
            'graphql_injection_detector',
            'header_injection_detector',
            'prototype_pollution_detector',
        ],
        'required_plan': 'pro',
    },

    # API SECURITY - API testing tools (Pro+)
    'api': {
        'name': 'API Security',
        'icon': '🔌',
        'description': 'REST, GraphQL, API documentation discovery',
        'detectors': [
            'api_security_detector',
            'graphql_detector',
            'api_docs_discovery',
            'jwt_detector',
            'jwt_vulnerability_scanner',
            'oauth_detector',
        ],
        'required_plan': 'pro',
    },

    # SSRF & OOB - Out-of-band testing (Enterprise only)
    'ssrf': {
        'name': 'SSRF & OOB',
        'icon': '🔗',
        'description': 'Server-Side Request Forgery & Out-of-Band attacks',
        'detectors': [
            'ssrf_detector',
            'advanced_ssrf_detector',
            'ssrf_oob_detector',
            'ssrf_oob_advanced_detector',
        ],
        'required_plan': 'enterprise',
    },

    # AUTHENTICATION - Auth testing (Pro+)
    'auth': {
        'name': 'Authentication',
        'icon': '🔐',
        'description': 'Authentication bypass, brute force, session attacks',
        'detectors': [
            'auth_bypass_detector',
            'brute_force_detector',
            'rate_limit_bypass_detector',
            'race_condition_detector',
        ],
        'required_plan': 'pro',
    },

    # BUSINESS LOGIC - Logic flaws (Enterprise)
    'business_logic': {
        'name': 'Business Logic',
        'icon': '💼',
        'description': 'Business logic flaws, IDOR, access control',
        'detectors': [
            'idor_detector',
            'ffuf_idor_detector',
            'cache_poisoning_detector',
            'business_logic_detector',
        ],
        'required_plan': 'enterprise',
    },

    # 0-DAY HUNTING - Advanced recon techniques (Pro+)
    'zero_day': {
        'name': '0-Day Hunting',
        'icon': '🔥',
        'description': 'Elite bug bounty recon techniques for uncovering high-impact issues',
        'detectors': [
            'js_file_analyzer',
            'backup_file_hunter',
            'api_docs_discovery',
            'parameter_fuzzer',
            'old_domain_hunter',
            'github_osint',
        ],
        'required_plan': 'pro',
    },

    # RECONNAISSANCE - Information gathering (All plans)
    'recon': {
        'name': 'Reconnaissance',
        'icon': '🔍',
        'description': 'Subdomain discovery, HTTP probing, crawling, secret detection, file hunting',
        'detectors': [
            'subfinder_detector',
            'amass_detector',
            'httpx_detector',
            'katana_detector',
            'gf_pattern_detector',
            'nmap_detector',
            'subdomain_takeover_detector',
            'secret_detector',
            'js_file_analyzer',
            'backup_file_hunter',
            'simple_file_list_detector',
            'old_domain_hunter',
            'github_osint',
        ],
        'required_plan': 'free',
    },

    # MOBILE SECURITY - Android APK and iOS IPA static analysis (Pro+)
    'mobile': {
        'name': 'Mobile Security',
        'icon': '📱',
        'description': 'Android APK and iOS IPA static security analysis',
        'detectors': [
            'apk_analyzer_detector',
            'ios_scanner_detector',
        ],
        'required_plan': 'pro',
    },

    # FUZZING - Advanced fuzzing (Pro+)
    'fuzzing': {
        'name': 'Fuzzing',
        'icon': '⚡',
        'description': 'Parameter fuzzing, IDOR fuzzing (ffuf), file upload, CVE scanning',
        'detectors': [
            'basic_param_fuzzer',
            'parameter_fuzzer',
            'ffuf_idor_detector',
            'fuzz_detector',
            'file_upload_detector',
            'cve_database_detector',
            'nuclei_detector',
        ],
        'required_plan': 'pro',
    },
}


# Plan-based access levels
PLAN_ACCESS = {
    'free': ['web', 'recon'],
    'pro': ['web', 'recon', 'zero_day', 'injection', 'api', 'auth', 'fuzzing', 'mobile'],
    'enterprise': ['web', 'recon', 'zero_day', 'injection', 'api', 'auth', 'fuzzing', 'ssrf', 'business_logic', 'mobile'],
}


def get_allowed_detectors_for_plan(plan_name: str) -> list:
    """
    Get list of all detector names allowed for a specific plan.

    Args:
        plan_name: Plan name ('free', 'pro', 'enterprise')

    Returns:
        List of detector names
    """
    categories_out, allowed_detectors = _try_db_plan_context(plan_name)
    if allowed_detectors is not None:
        return sorted(allowed_detectors)

    plan_key = (plan_name or '').lower()
    allowed_categories = PLAN_ACCESS.get(plan_key, [])
    detectors = []

    for category_key in allowed_categories:
        category = DETECTOR_CATEGORIES.get(category_key, {})
        detectors.extend(category.get('detectors', []))

    return detectors


def get_detector_category(detector_name: str) -> dict:
    """
    Get category information for a specific detector.

    Args:
        detector_name: Name of the detector

    Returns:
        Dict with category info or None
    """
    for category_key, category_data in DETECTOR_CATEGORIES.items():
        if detector_name in category_data['detectors']:
            return {
                'key': category_key,
                'name': category_data['name'],
                'icon': category_data['icon'],
                'required_plan': category_data['required_plan'],
            }
    return None


def is_detector_allowed_for_plan(detector_name: str, plan_name: str) -> bool:
    """
    Check if a detector is allowed for a specific plan.

    Args:
        detector_name: Name of the detector
        plan_name: Plan name ('free', 'pro', 'enterprise')

    Returns:
        bool
    """
    categories_out, allowed_detectors = _try_db_plan_context(plan_name)
    if allowed_detectors is not None:
        return detector_name in allowed_detectors
    allowed = get_allowed_detectors_for_plan(plan_name)
    return detector_name in allowed


def get_categories_for_plan(plan_name: str) -> list:
    """
    Get all categories with their detectors for a specific plan.
    Marks each detector as locked/unlocked based on plan.

    Args:
        plan_name: Plan name ('free', 'pro', 'enterprise')

    Returns:
        List of category dicts with detector info
    """
    categories_out, allowed_detectors = _try_db_plan_context(plan_name)
    if categories_out is not None:
        return categories_out

    plan_key = (plan_name or '').lower()
    allowed_categories = PLAN_ACCESS.get(plan_key, [])
    result = []

    for category_key, category_data in DETECTOR_CATEGORIES.items():
        is_allowed = category_key in allowed_categories

        result.append({
            'key': category_key,
            'name': category_data['name'],
            'icon': category_data['icon'],
            'description': category_data['description'],
            'required_plan': category_data['required_plan'],
            'is_allowed': is_allowed,
            'detectors': [
                {
                    'name': detector,
                    'is_allowed': is_allowed,
                }
                for detector in category_data['detectors']
            ],
            'detector_count': len(category_data['detectors']),
        })

    return result


def guess_category_for_detectors(detector_names: list) -> Optional[dict]:
    """Best-effort category guess for a detector selection.

    This is used for UI display (e.g. Dashboard "Type") when scans are created
    via detector-category selection and the legacy scan_type is not meaningful.
    """
    if not detector_names:
        return None

    selected = {d for d in detector_names if isinstance(d, str) and d}
    if not selected:
        return None

    # Prefer DB-backed categories if available.
    try:
        from scans.category_models import ScanCategory, DetectorConfig

        selected = {d for d in detector_names if isinstance(d, str) and d}
        if not selected:
            return None

        best = None
        best_score = 0.0
        cats = ScanCategory.objects.filter(is_active=True)
        for cat in cats:
            cat_detectors = set(
                DetectorConfig.objects.filter(is_active=True, categories=cat).values_list('name', flat=True)
            )
            if not cat_detectors:
                continue
            intersection = selected.intersection(cat_detectors)
            if not intersection:
                continue

            overlap_ratio = len(intersection) / max(1, len(selected))
            coverage_ratio = len(intersection) / max(1, len(cat_detectors))
            score = overlap_ratio * 0.7 + coverage_ratio * 0.3
            if score > best_score:
                best_score = score
                best = {
                    'key': getattr(cat, 'name', None) or 'unknown',
                    'name': getattr(cat, 'display_name', None) or getattr(cat, 'name', 'unknown'),
                    'icon': getattr(cat, 'icon', None),
                }

        if not best or best_score < 0.55:
            return None
        return best
    except Exception:
        pass

    best = None
    best_score = 0.0

    for category_key, category_data in DETECTOR_CATEGORIES.items():
        category_detectors = set(category_data.get('detectors', []) or [])
        if not category_detectors:
            continue

        intersection = selected.intersection(category_detectors)
        if not intersection:
            continue

        overlap_ratio = len(intersection) / max(1, len(selected))
        coverage_ratio = len(intersection) / max(1, len(category_detectors))
        score = overlap_ratio * 0.7 + coverage_ratio * 0.3

        if score > best_score:
            best_score = score
            best = {
                'key': category_key,
                'name': category_data.get('name', category_key),
                'icon': category_data.get('icon'),
            }

    # Avoid misleading labels for tiny/noisy selections.
    if not best or best_score < 0.55:
        return None
    return best
