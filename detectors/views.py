from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from scans.category_models import ScanCategory, DetectorConfig


class DetectorCategoryViewSet(viewsets.ViewSet):
    """
    API endpoint for detector categories and plan-based access control.
    Shows which detectors are available for the user's current plan.
    """
    permission_classes = [AllowAny]  # Public for browsing, but shows plan restrictions

    def list(self, request):
        """
        Get all detector categories with plan-based access info.
        If authenticated, shows which are allowed for user's plan.
        If not authenticated, shows as if on Free plan.
        """
        from django.conf import settings

        plan_name = 'free'
        overrides_by_category_id = {}

        # In free mode, categories are not locked by subscription.
        paid_enabled = bool(getattr(settings, 'PAID_PLANS_ENABLED', False))

        dangerous_allowed = True  # open-source: all tools available by default
        if request.user.is_authenticated:
            dangerous_allowed = True

        # If paid plans are enabled, keep existing category gating behavior.
        if paid_enabled and request.user.is_authenticated:
            try:
                from usage.models import Subscription, Plan, PlanScanCategoryOverride

                subscription = Subscription.objects.filter(
                    user=request.user,
                    status__in=['active', 'trialing'],
                ).select_related('plan').first()
                if subscription and getattr(subscription, 'plan', None):
                    plan_name = subscription.plan.name
                    plan_obj = subscription.plan
                else:
                    plan_obj = None

                if plan_obj is None:
                    plan_obj = Plan.objects.filter(name=plan_name).only('id').first()

                if plan_obj is not None:
                    overrides_by_category_id = {
                        o.category_id: bool(o.is_allowed)
                        for o in PlanScanCategoryOverride.objects.filter(plan=plan_obj).only('category_id', 'is_allowed')
                    }

                try:
                    dangerous_allowed = bool(subscription.can_use_dangerous_tools()) if subscription else False
                except Exception:
                    dangerous_allowed = False
            except Exception:
                overrides_by_category_id = {}

        categories_out = []
        categories_qs = ScanCategory.objects.filter(is_active=True).order_by('order', 'name')
        for cat in categories_qs:
            if paid_enabled:
                has_access = cat.can_be_used_by_plan(plan_name)
                if cat.id in overrides_by_category_id:
                    has_access = overrides_by_category_id[cat.id]
            else:
                has_access = True

            detectors_qs = (
                DetectorConfig.objects.filter(is_active=True, categories=cat)
                .order_by('execution_order', 'name')
            )

            det_out = []
            for det in detectors_qs:
                det_allowed = bool(has_access) and (not det.is_dangerous or dangerous_allowed)
                det_out.append({
                    'name': det.name,
                    'display_name': det.display_name,
                    'description': det.description,
                    'severity': det.severity,
                    'tags': det.tags,
                    'is_dangerous': det.is_dangerous,
                    'requires_oob': det.requires_oob,
                    'is_beta': det.is_beta,
                    'execution_order': det.execution_order,
                    'is_allowed': det_allowed,
                })

            categories_out.append({
                'key': cat.name,
                'name': cat.display_name,
                'icon': cat.icon,
                'description': cat.description,
                'required_plan': cat.required_plan,
                'is_allowed': bool(has_access),
                'detectors': det_out,
                'detector_count': len(det_out),
            })

        return Response({
            'current_plan': plan_name,
            'categories': categories_out,
            'total_categories': len(categories_out),
            'unlocked_categories': len([c for c in categories_out if c.get('is_allowed')]),
            'dangerous_tools_allowed': bool(dangerous_allowed),
        })

    @action(detail=False, methods=['get'])
    def allowed(self, request):
        """
        Get only the allowed detectors for user's plan (useful for scan creation).
        """
        from django.conf import settings

        plan_name = 'free'
        overrides_by_category_id = {}
        paid_enabled = bool(getattr(settings, 'PAID_PLANS_ENABLED', False))

        dangerous_allowed = bool(request.user.is_authenticated and getattr(request.user, 'is_verified', False))

        if paid_enabled and request.user.is_authenticated:
            try:
                from usage.models import Subscription, Plan, PlanScanCategoryOverride

                subscription = Subscription.objects.filter(
                    user=request.user,
                    status__in=['active', 'trialing'],
                ).select_related('plan').first()
                if subscription and getattr(subscription, 'plan', None):
                    plan_name = subscription.plan.name
                    plan_obj = subscription.plan
                else:
                    plan_obj = None

                if plan_obj is None:
                    plan_obj = Plan.objects.filter(name=plan_name).only('id').first()

                if plan_obj is not None:
                    overrides_by_category_id = {
                        o.category_id: bool(o.is_allowed)
                        for o in PlanScanCategoryOverride.objects.filter(plan=plan_obj).only('category_id', 'is_allowed')
                    }

                try:
                    dangerous_allowed = bool(subscription.can_use_dangerous_tools()) if subscription else False
                except Exception:
                    dangerous_allowed = False
            except Exception:
                overrides_by_category_id = {}

        allowed_detectors = []
        allowed_categories = []

        for cat in ScanCategory.objects.filter(is_active=True).order_by('order', 'name'):
            if paid_enabled:
                cat_allowed = cat.can_be_used_by_plan(plan_name)
                if cat.id in overrides_by_category_id:
                    cat_allowed = overrides_by_category_id[cat.id]
            else:
                cat_allowed = True

            if not cat_allowed:
                continue
            allowed_categories.append(cat.name)
            for det in DetectorConfig.objects.filter(is_active=True, categories=cat):
                if det.is_dangerous and not dangerous_allowed:
                    continue
                allowed_detectors.append(det.name)

        # de-dupe while keeping stable ordering
        allowed_detectors = list(dict.fromkeys(allowed_detectors))

        return Response({
            'plan': plan_name,
            'allowed_categories': allowed_categories,
            'allowed_detectors': allowed_detectors,
            'detector_count': len(allowed_detectors),
            'dangerous_tools_allowed': bool(dangerous_allowed),
        })

    @action(detail=False, methods=['post'])
    def validate(self, request):
        """
        Validate if a list of detectors is allowed for user's plan.
        Request body: {"detectors": ["detector1", "detector2", ...]}
        """
        requested = request.data.get('detectors', [])

        from django.conf import settings

        plan_name = 'free'
        overrides_by_category_id = {}
        paid_enabled = bool(getattr(settings, 'PAID_PLANS_ENABLED', False))

        dangerous_allowed = bool(request.user.is_authenticated and getattr(request.user, 'is_verified', False))

        if paid_enabled and request.user.is_authenticated:
            try:
                from usage.models import Subscription, Plan, PlanScanCategoryOverride

                subscription = Subscription.objects.filter(
                    user=request.user,
                    status__in=['active', 'trialing'],
                ).select_related('plan').first()
                if subscription and getattr(subscription, 'plan', None):
                    plan_name = subscription.plan.name
                    plan_obj = subscription.plan
                else:
                    plan_obj = None

                if plan_obj is None:
                    plan_obj = Plan.objects.filter(name=plan_name).only('id').first()

                if plan_obj is not None:
                    overrides_by_category_id = {
                        o.category_id: bool(o.is_allowed)
                        for o in PlanScanCategoryOverride.objects.filter(plan=plan_obj).only('category_id', 'is_allowed')
                    }

                try:
                    dangerous_allowed = bool(subscription.can_use_dangerous_tools()) if subscription else False
                except Exception:
                    dangerous_allowed = False
            except Exception:
                overrides_by_category_id = {}

        # Build allowed set
        allowed_set = set()
        for cat in ScanCategory.objects.filter(is_active=True):
            if paid_enabled:
                cat_allowed = cat.can_be_used_by_plan(plan_name)
                if cat.id in overrides_by_category_id:
                    cat_allowed = overrides_by_category_id[cat.id]
            else:
                cat_allowed = True

            if not cat_allowed:
                continue
            for det in DetectorConfig.objects.filter(is_active=True, categories=cat):
                if det.is_dangerous and not dangerous_allowed:
                    continue
                allowed_set.add(det.name)

        results = []
        all_allowed = True
        for d in requested or []:
            ok = d in allowed_set
            if not ok:
                all_allowed = False
            results.append({'detector': d, 'is_allowed': ok})

        return Response({'plan': plan_name, 'all_allowed': all_allowed, 'results': results})
