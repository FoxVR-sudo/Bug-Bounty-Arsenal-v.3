"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf import settings
from django.urls import path, include
from django.http import Http404
from django.views.generic import RedirectView
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from users.views import UserViewSet
from users.auth_views import (
    login_view,
    logout_view,
    oidc_login_view,
    signup_confirm_phone_view,
    signup_enterprise_confirm_phone_view,
    signup_enterprise_resend_phone_view,
    signup_enterprise_start_view,
    signup_enterprise_view,
    signup_resend_phone_view,
    signup_start_view,
    signup_view,
    token_refresh_view,
)
from users.jwt_views import TwoFactorTokenObtainPairView
from users.email_views import (
    request_email_verification,
    request_password_reset,
    reset_password,
    verify_email,
)
from users.landing_views import (
    about_page,
    api_reference_page,
    blog_page,
    careers_page,
    compliance_page,
    contact_page,
    dashboard_page,
    docs_page,
    landing_page,
    login_page,
    pricing_page,
    privacy_page,
    security_page,
    signup_page,
    terms_page,
)
from users.api_views import (
    get_current_user,
    get_supported_countries,
    resend_phone_verification,
    search_company,
    send_phone_verification,
    verify_company,
    verify_phone_code,
)
from users.two_factor_views import (
    two_factor_status_view,
    two_factor_setup_view,
    two_factor_confirm_view,
    two_factor_disable_view,
    two_factor_regenerate_backup_codes_view,
)
from users.admin_views import (
    admin_stats, admin_users_list, admin_user_activate, admin_user_deactivate,
    admin_scans_list, admin_database_backup, admin_database_restore,
    admin_system_health, admin_celery_status, admin_clear_cache, admin_scan_metrics
)
from scans.views import (
    ScanViewSet, AuditLogViewSet, ApiKeyViewSet, VulnerabilityViewSet,
    scan_status_view, scan_start_view, scan_stop_view, validate_scope_view
)
from scans.zap_views import zap_scan_start, zap_scan_status, zap_scan_cancel
from scans.mobile_views import mobile_scan_start, mobile_scan_status
from scans.export_views import export_pdf_view, export_json_view, export_csv_view
from scans.demo_view import demo_scan_view
from scans.category_views import (
    ScanCategoryViewSet, start_category_scan, get_detector_statistics
)
from scans.domain_verification_views import (
    initiate_domain_verification,
    check_domain_verification,
    list_verified_domains,
    delete_domain_verification,
)
from detectors.views import DetectorCategoryViewSet
from subscriptions.views import SubscriptionViewSet
from subscriptions.billing_views import (
    create_checkout_session, billing_portal, buy_extra_scans, change_tier
)
from subscriptions.api_views import (
    get_plans, get_current_subscription, cancel_subscription,
    change_plan, reactivate_subscription, sync_subscription, upgrade_to_enterprise
)

from users.team_views import TeamViewSet
from users.integration_views import IntegrationViewSet
from users.audit_views import ScanAuditLogViewSet

from users.session_views import (
    sessions_list_view,
    sessions_revoke_view,
    sessions_revoke_all_view,
)

from config.health_views import healthz_view, readyz_view

# DRF Router
router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'scan-categories', ScanCategoryViewSet, basename='scan-category')
router.register(r'detector-categories', DetectorCategoryViewSet, basename='detector-category')
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')
router.register(r'scan-audit-logs', ScanAuditLogViewSet, basename='scan-audit-log')
router.register(r'api-keys', ApiKeyViewSet, basename='apikey')
# router.register(r'plans', PlanViewSet, basename='plan')  # Using custom endpoint instead
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r'teams', TeamViewSet, basename='team')
router.register(r'integrations', IntegrationViewSet, basename='integration')

urlpatterns = [
    # Health probes (no auth)
    path('healthz/', healthz_view, name='healthz'),
    path('readyz/', readyz_view, name='readyz'),

    # Landing page
    path('', landing_page, name='landing'),

    # Auth pages (HTML forms)
    path('login/', login_page, name='login-page'),
    path('signup/', signup_page, name='signup-page'),
    path('pricing/', pricing_page, name='pricing-page'),

    # Dashboard (requires authentication)
    path('dashboard/', dashboard_page, name='dashboard'),

    # Footer pages
    path('docs/', docs_page, name='docs'),
    path('api/', api_reference_page, name='api-reference'),
    path('about/', about_page, name='about'),
    path('blog/', blog_page, name='blog'),
    path('careers/', careers_page, name='careers'),
    path('contact/', contact_page, name='contact'),
    path('privacy/', privacy_page, name='privacy'),
    path('terms/', terms_page, name='terms'),
    path('security/', security_page, name='security'),
    path('compliance/', compliance_page, name='compliance'),

    # Admin panel at secret URL — /admin/ returns 404
    path('admin/', lambda request: (_ for _ in ()).throw(Http404())),
    path(f'{settings.ADMIN_URL}/', admin.site.urls),

    # Favicon redirect
    path('favicon.ico', RedirectView.as_view(url='/static/favicon.svg', permanent=True)),

    # Authentication endpoints (must be before api/ include)
    path('api/auth/login/', login_view, name='auth-login'),
    path('api/auth/oidc/login/', oidc_login_view, name='auth-oidc-login'),
    path('api/auth/signup/start/', signup_start_view, name='auth-signup-start'),
    path('api/auth/signup/confirm-phone/', signup_confirm_phone_view, name='auth-signup-confirm-phone'),
    path('api/auth/signup/resend-phone/', signup_resend_phone_view, name='auth-signup-resend-phone'),
    path(
        'api/auth/signup-enterprise/start/',
        signup_enterprise_start_view,
        name='auth-signup-enterprise-start',
    ),
    path(
        'api/auth/signup-enterprise/confirm-phone/',
        signup_enterprise_confirm_phone_view,
        name='auth-signup-enterprise-confirm-phone',
    ),
    path(
        'api/auth/signup-enterprise/resend-phone/',
        signup_enterprise_resend_phone_view,
        name='auth-signup-enterprise-resend-phone',
    ),
    path('api/auth/signup/', signup_view, name='auth-signup'),
    path('api/auth/signup-enterprise/', signup_enterprise_view, name='auth-signup-enterprise'),
    path('api/auth/refresh/', token_refresh_view, name='auth-refresh'),
    path('api/auth/logout/', logout_view, name='auth-logout'),
    path('api/auth/me/', get_current_user, name='current-user'),

    # Session / device management
    path('api/auth/sessions/', sessions_list_view, name='auth-sessions'),
    path('api/auth/sessions/revoke/', sessions_revoke_view, name='auth-sessions-revoke'),
    path('api/auth/sessions/revoke-all/', sessions_revoke_all_view, name='auth-sessions-revoke-all'),

    # Email verification & password reset
    path('api/auth/request-verification/', request_email_verification, name='request-verification'),
    path('api/auth/verify-email/', verify_email, name='verify-email'),
    path('api/auth/request-reset/', request_password_reset, name='request-password-reset'),
    path('api/auth/reset-password/', reset_password, name='reset-password'),

    # Two-factor authentication (TOTP)
    path('api/auth/2fa/status/', two_factor_status_view, name='two-factor-status'),
    path('api/auth/2fa/setup/', two_factor_setup_view, name='two-factor-setup'),
    path('api/auth/2fa/confirm/', two_factor_confirm_view, name='two-factor-confirm'),
    path('api/auth/2fa/disable/', two_factor_disable_view, name='two-factor-disable'),
    path('api/auth/2fa/backup-codes/regenerate/',
         two_factor_regenerate_backup_codes_view,
         name='two-factor-backup-codes-regenerate'),

    # NEW v3.0: Phone & Company Verification endpoints
    path('api/users/verify-phone/send/', send_phone_verification, name='send-phone-verification'),
    path('api/users/verify-phone/confirm/', verify_phone_code, name='verify-phone-code'),
    path('api/users/verify-phone/resend/', resend_phone_verification, name='resend-phone-verification'),
    path('api/users/verify-company/', verify_company, name='verify-company'),
    path('api/users/search-company/', search_company, name='search-company'),
    path('api/users/supported-countries/', get_supported_countries, name='supported-countries'),

    # Public demo endpoint (no auth)
    path('api/demo/scan/', demo_scan_view, name='demo-scan'),

    # Scan endpoints (custom actions - must be before router)
    path('api/scans/status/', scan_status_view, name='scan-status'),
    path('api/scans/start/', scan_start_view, name='scan-start'),
    path('api/scans/stop/<str:scan_id>/', scan_stop_view, name='scan-stop'),
    path('api/scans/validate-scope/', validate_scope_view, name='validate-scope'),
    path('api/scans/<int:scan_id>/pdf/', export_pdf_view, name='scan-export-pdf'),
    path('api/scans/<int:scan_id>/json/', export_json_view, name='scan-export-json'),
    path('api/scans/<int:scan_id>/csv/', export_csv_view, name='scan-export-csv'),

    # OWASP ZAP component
    path('api/zap/scan/', zap_scan_start, name='zap-scan-start'),
    path('api/zap/scan/<int:scan_id>/', zap_scan_status, name='zap-scan-status'),
    path('api/zap/scan/<int:scan_id>/cancel/', zap_scan_cancel, name='zap-scan-cancel'),

    # Mobile app scanner (APK / IPA upload)
    path('api/mobile/scan/', mobile_scan_start, name='mobile-scan-start'),
    path('api/mobile/scan/<int:scan_id>/', mobile_scan_status, name='mobile-scan-status'),

    # Domain ownership verification (required for dangerous scanners)
    path('api/domain-verify/', list_verified_domains, name='domain-verify-list'),
    path('api/domain-verify/initiate/', initiate_domain_verification, name='domain-verify-initiate'),
    path('api/domain-verify/check/', check_domain_verification, name='domain-verify-check'),
    path('api/domain-verify/<str:domain>/', delete_domain_verification, name='domain-verify-delete'),

    # NEW v3.0: Category-based scan endpoints
    path('api/scans/start-category-scan/', start_category_scan, name='start-category-scan'),
    path('api/detectors/statistics/', get_detector_statistics, name='detector-statistics'),

    # NEW v3.1: Plan and subscription endpoints
    path('api/plans/', get_plans, name='plans-list'),
    path('api/subscriptions/current/', get_current_subscription, name='subscription-current'),
    path('api/subscriptions/cancel/', cancel_subscription, name='subscription-cancel'),
    path('api/subscriptions/change-plan/', change_plan, name='subscription-change-plan'),
    path('api/subscriptions/reactivate/', reactivate_subscription, name='subscription-reactivate'),
    path('api/subscriptions/sync/', sync_subscription, name='subscription-sync'),
    path('api/subscriptions/upgrade-to-enterprise/', upgrade_to_enterprise, name='subscription-upgrade-enterprise'),

    # Billing endpoints
    path('api/billing/checkout/', create_checkout_session, name='billing-checkout'),
    path('api/billing/portal/', billing_portal, name='billing-portal'),
    path('api/billing/buy-scans/', buy_extra_scans, name='buy-extra-scans'),
    path('api/subscriptions/change-tier/', change_tier, name='change-tier'),

    # Stripe webhook
    path('api/webhooks/stripe/', include('subscriptions.urls')),

    # Admin endpoints (requires admin/staff permissions)
    path('api/admin/stats/', admin_stats, name='admin-stats'),
    path('api/admin/users/', admin_users_list, name='admin-users-list'),
    path('api/admin/users/<str:user_id>/activate/', admin_user_activate, name='admin-user-activate'),
    path('api/admin/users/<str:user_id>/deactivate/', admin_user_deactivate, name='admin-user-deactivate'),
    path('api/admin/scans/', admin_scans_list, name='admin-scans-list'),
    path('api/admin/database/backup/', admin_database_backup, name='admin-database-backup'),
    path('api/admin/database/restore/', admin_database_restore, name='admin-database-restore'),
    path('api/admin/system-health/', admin_system_health, name='admin-system-health'),
    path('api/admin/celery-status/', admin_celery_status, name='admin-celery-status'),
    path('api/admin/scan-metrics/', admin_scan_metrics, name='admin-scan-metrics'),
    path('api/admin/clear-cache/', admin_clear_cache, name='admin-clear-cache'),

    # API endpoints (router - more general patterns)
    path('api/', include((router.urls, 'api'), namespace='api')),

    # JWT Authentication
    path('api/token/', TwoFactorTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # Browsable API login/logout
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
