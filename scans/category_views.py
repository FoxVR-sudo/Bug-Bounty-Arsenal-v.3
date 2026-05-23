"""
API Views for Scan Categories and Category-based Scanning (v3.0)
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.shortcuts import get_object_or_404

from scans.category_models import ScanCategory, DetectorConfig
from scans.models import Scan
from scans.serializers import ScanSerializer
from subscriptions.models import Subscription, Plan, PlanScanCategoryOverride

from users.scan_audit import create_scan_audit_log

from .exceptions import ScanBrokerUnavailable, ScanQueueUnavailable

from .throttles import ScanStartRateThrottle


class ScanCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoints for browsing scan categories.

    Endpoints:
    - GET /api/scan-categories/ - List all available categories (filtered by user plan)
    - GET /api/scan-categories/{id}/ - Get category details with detector list
    - GET /api/scan-categories/{id}/detectors/ - Get detectors for category
    """
    queryset = ScanCategory.objects.filter(is_active=True)
    permission_classes = [AllowAny]  # Public access to view categories

    def get_queryset(self):
        """Filter categories by user's subscription plan"""
        from django.conf import settings

        if not bool(getattr(settings, 'PAID_PLANS_ENABLED', False)):
            return ScanCategory.objects.filter(is_active=True)

        # Get user's plan
        user_plan = 'free'
        plan_obj = None
        if self.request.user.is_authenticated:
            try:
                subscription = Subscription.objects.get(user=self.request.user, status__in=['active', 'trialing'])
                user_plan = subscription.plan.name
                plan_obj = subscription.plan
            except Subscription.DoesNotExist:
                user_plan = 'free'

        if plan_obj is None:
            plan_obj = Plan.objects.filter(name=user_plan).only('id').first()

        overrides_by_category_id = {}
        if plan_obj is not None:
            overrides_by_category_id = {
                o.category_id: bool(o.is_allowed)
                for o in PlanScanCategoryOverride.objects.filter(plan=plan_obj).only('category_id', 'is_allowed')
            }

        # Filter categories by plan access
        queryset = ScanCategory.objects.filter(is_active=True)
        accessible_categories = []

        for category in queryset:
            has_access = category.can_be_used_by_plan(user_plan)
            if category.id in overrides_by_category_id:
                has_access = overrides_by_category_id[category.id]
            if has_access:
                accessible_categories.append(category.id)

        return queryset.filter(id__in=accessible_categories)

    def list(self, request):
        """List all scan categories with access status"""
        from django.conf import settings

        # Get ALL categories, not just accessible ones
        all_categories = ScanCategory.objects.filter(is_active=True)

        if not bool(getattr(settings, 'PAID_PLANS_ENABLED', False)):
            data = []
            for category in all_categories:
                detector_count = category.detectors.filter(is_active=True).count()
                dangerous_count = category.detectors.filter(is_active=True, is_dangerous=True).count()
                data.append({
                    'id': category.id,
                    'name': category.name,
                    'display_name': category.display_name,
                    'description': category.description,
                    'icon': category.icon,
                    'icon_emoji': category.icon,
                    'required_plan': category.required_plan,
                    'detector_count': detector_count,
                    'dangerous_detector_count': dangerous_count,
                    'is_enterprise_only': False,
                    'has_access': True,
                })
            return Response(data)

        # Get user's plan
        user_plan = 'free'
        plan_obj = None
        if request.user.is_authenticated:
            try:
                subscription = Subscription.objects.filter(user=request.user, status='active').first()
                if subscription:
                    user_plan = subscription.plan.name
                    plan_obj = subscription.plan
            except Exception:
                pass

        if plan_obj is None:
            plan_obj = Plan.objects.filter(name=user_plan).only('id').first()

        overrides_by_category_id = {}
        if plan_obj is not None:
            overrides_by_category_id = {
                o.category_id: bool(o.is_allowed)
                for o in PlanScanCategoryOverride.objects.filter(plan=plan_obj).only('category_id', 'is_allowed')
            }

        data = []
        for category in all_categories:
            detector_count = category.detectors.filter(is_active=True).count()
            dangerous_count = category.detectors.filter(is_active=True, is_dangerous=True).count()
            has_access = category.can_be_used_by_plan(user_plan)
            if category.id in overrides_by_category_id:
                has_access = overrides_by_category_id[category.id]

            data.append({
                'id': category.id,
                'name': category.name,
                'display_name': category.display_name,
                'description': category.description,
                'icon': category.icon,
                'icon_emoji': category.icon,  # Alias for frontend compatibility
                'required_plan': category.required_plan,
                'detector_count': detector_count,
                'dangerous_detector_count': dangerous_count,
                'is_enterprise_only': category.required_plan == 'enterprise',
                'has_access': has_access,  # Frontend can use this
            })

        return Response(data)

    def retrieve(self, request, pk=None):
        """Get category details with detector list"""
        # Get any active category, not just accessible ones (for upgrade page)
        category = get_object_or_404(ScanCategory.objects.filter(is_active=True), pk=pk)

        # Get detectors for this category
        detectors = category.get_detectors()

        detector_list = []
        for detector in detectors:
            detector_list.append({
                'id': detector.id,
                'name': detector.name,
                'display_name': detector.display_name,
                'description': detector.description,
                'severity': detector.severity,
                'tags': detector.tags,
                'is_dangerous': detector.is_dangerous,
                'requires_oob': detector.requires_oob,
                'is_beta': detector.is_beta,
                'execution_order': detector.execution_order,
            })

        data = {
            'id': category.id,
            'name': category.name,
            'display_name': category.display_name,
            'description': category.description,
            'icon': category.icon,
            'icon_emoji': category.icon,  # Alias for frontend compatibility
            'required_plan': category.required_plan,
            'detector_count': len(detector_list),
            'detectors': detector_list,
        }

        return Response(data)

    @action(detail=True, methods=['get'])
    def detectors(self, request, pk=None):
        """Get detectors for a specific category"""
        # Get any active category, not just accessible ones (for upgrade page)
        category = get_object_or_404(ScanCategory.objects.filter(is_active=True), pk=pk)
        detectors = category.get_detectors()

        data = []
        for detector in detectors:
            data.append({
                'id': detector.id,
                'name': detector.name,
                'display_name': detector.display_name,
                'description': detector.description,
                'severity': detector.severity,
                'tags': detector.tags,
                'is_dangerous': detector.is_dangerous,
                'requires_oob': detector.requires_oob,
                'execution_order': detector.execution_order,
                'statistics': {
                    'total_executions': detector.total_executions,
                    'total_findings': detector.total_findings,
                    'average_execution_time': detector.average_execution_time,
                }
            })

        return Response(data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanStartRateThrottle])
def start_category_scan(request):
    """
    Start a new scan using a category.

    POST /api/scans/start-category-scan/
    {
        "target": "https://example.com",
        "category": "web",  // or category ID
        "detectors": ["xss_pattern_detector", "sql_pattern_detector"],  // optional, empty = all
        "options": {
            "concurrency": 10,
            "timeout": 30
        }
    }
    """
    user = request.user

    from rest_framework import serializers
    consent_value = request.data.get('consent')
    try:
        consent_value = serializers.BooleanField().to_internal_value(consent_value)
    except Exception:
        consent_value = False

    if consent_value is not True:
        return Response(
            {
                'error': 'Consent is required. You must confirm you have authorization to scan this target.',
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get request data
    target = request.data.get('target')
    category_identifier = request.data.get('category')
    selected_detectors = request.data.get('detectors', [])
    options = request.data.get('options', {})

    # Validate input
    if not target:
        return Response(
            {'error': 'Target URL is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if not category_identifier:
        return Response(
            {'error': 'Category is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get category
    try:
        if isinstance(category_identifier, int) or category_identifier.isdigit():
            category = ScanCategory.objects.get(id=int(category_identifier), is_active=True)
        else:
            category = ScanCategory.objects.get(name=category_identifier, is_active=True)
    except ScanCategory.DoesNotExist:
        return Response(
            {'error': f'Category "{category_identifier}" not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    from django.conf import settings

    # Validate selected detectors
    if selected_detectors:
        # Check if detectors exist in category
        category_detector_names = list(
            category.detectors.filter(is_active=True).values_list('name', flat=True)
        )

        invalid_detectors = [d for d in selected_detectors if d not in category_detector_names]
        if invalid_detectors:
            return Response(
                {
                    'error': 'Invalid detectors for this category',
                    'invalid_detectors': invalid_detectors,
                    'available_detectors': category_detector_names,
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if dangerous detectors are included
        dangerous_detectors = category.detectors.filter(
            name__in=selected_detectors,
            is_dangerous=True
        )

        if dangerous_detectors.exists() and bool(
            getattr(settings, 'DANGEROUS_TOOLS_REQUIRE_EMAIL_VERIFICATION', True)
        ):
            if not bool(getattr(user, 'is_verified', False)):
                dangerous_names = list(dangerous_detectors.values_list('name', flat=True))
                return Response(
                    {
                        'error': 'Email verification required to run dangerous scanners.',
                        'dangerous_detectors': dangerous_names,
                        'requires_email_verification': True,
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

        # Domain ownership check — required for dangerous detectors
        if dangerous_detectors.exists():
            from scans.models import DomainVerification
            if not DomainVerification.is_domain_verified_for_user(user, target):
                apex = DomainVerification.extract_apex_domain(target)
                dangerous_names = list(dangerous_detectors.values_list('name', flat=True))
                return Response(
                    {
                        'error': (
                            f'Domain ownership verification required to run dangerous scanners '
                            f'against {apex}. '
                            'Please verify you own this domain first at /domain-verify/.'
                        ),
                        'requires_domain_verification': True,
                        'domain': apex,
                        'dangerous_detectors': dangerous_names,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

    # If detectors list is empty => "all" detectors for category.
    if not selected_detectors:
        has_dangerous = category.detectors.filter(is_active=True, is_dangerous=True).exists()
        if has_dangerous and bool(
            getattr(settings, 'DANGEROUS_TOOLS_REQUIRE_EMAIL_VERIFICATION', True)
        ):
            if not bool(getattr(user, 'is_verified', False)):
                return Response(
                    {
                        'error': 'Email verification required to run dangerous scanners.',
                        'requires_email_verification': True,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

        # Domain ownership check for dangerous detectors
        if has_dangerous:
            from scans.models import DomainVerification
            if not DomainVerification.is_domain_verified_for_user(user, target):
                apex = DomainVerification.extract_apex_domain(target)
                return Response(
                    {
                        'error': (
                            f'Domain ownership verification required to run dangerous scanners '
                            f'against {apex}. '
                            'Please verify you own this domain first at /domain-verify/.'
                        ),
                        'requires_domain_verification': True,
                        'domain': apex,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

    # Create scan
    scan = Scan.objects.create(
        user=user,
        target=target,
        scan_category=category,
        selected_detectors=selected_detectors,
        status='pending',
    )

    # Audit log: scan created
    create_scan_audit_log(
        request=request,
        user=user,
        scan=scan,
        action='scan_created',
        target=target,
        metadata={
            'source': 'api:start-category-scan',
            'category': category.name,
            'detectors': selected_detectors,
            'options': options,
        },
    )

    # No subscription usage accounting in free mode

    # Start scan asynchronously (honor SCANS_AUTO_START like other scan endpoints)
    from django.conf import settings
    if getattr(settings, 'SCANS_AUTO_START', True):
        try:
            scan.start_async_scan(options)
            create_scan_audit_log(
                request=request,
                user=user,
                scan=scan,
                action='scan_started',
                target=target,
                metadata={
                    'source': 'api:start-category-scan',
                    'category': category.name,
                    'detectors': selected_detectors,
                    'options': options,
                },
            )
        except ScanBrokerUnavailable as e:
            scan.status = 'failed'
            scan.save(update_fields=['status'])
            create_scan_audit_log(
                request=request,
                user=user,
                scan=scan,
                action='scan_failed',
                target=target,
                metadata={
                    'source': 'api:start-category-scan',
                    'category': category.name,
                    'reason': 'broker_unavailable',
                },
                error_message=str(e),
            )
            raise ScanQueueUnavailable()
        except Exception as e:
            scan.status = 'failed'
            scan.save()
            create_scan_audit_log(
                request=request,
                user=user,
                scan=scan,
                action='scan_failed',
                target=target,
                metadata={
                    'source': 'api:start-category-scan',
                    'category': category.name,
                },
                error_message=str(e),
            )
            return Response(
                {'error': f'Failed to start scan: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    # Return scan details
    serializer = ScanSerializer(scan)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_detector_statistics(request):
    """
    Get statistics for all detectors.

    GET /api/detectors/statistics/
    """
    detectors = DetectorConfig.objects.filter(is_active=True).order_by('-total_findings')

    data = []
    for detector in detectors:
        data.append({
            'name': detector.name,
            'display_name': detector.display_name,
            'total_executions': detector.total_executions,
            'total_findings': detector.total_findings,
            'average_execution_time': detector.average_execution_time,
            'success_rate': (
                (detector.total_findings / detector.total_executions * 100)
                if detector.total_executions > 0 else 0
            ),
            'last_executed_at': detector.last_executed_at,
        })

    return Response(data)
