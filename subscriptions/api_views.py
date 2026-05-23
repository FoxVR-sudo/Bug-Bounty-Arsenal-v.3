"""
API views for subscription and plan management
"""
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from .models import Plan, Subscription
from .stripe_service import StripeService
import logging

logger = logging.getLogger(__name__)


def _paid_plans_disabled_response():
    if not bool(getattr(settings, 'PAID_PLANS_ENABLED', True)):
        payload = {
            'error': 'Paid plans and subscriptions are temporarily disabled.',
        }
        donate_url = str(getattr(settings, 'DONATE_URL', '') or '').strip()
        if donate_url:
            payload['donate_url'] = donate_url
        return Response(payload, status=status.HTTP_410_GONE)
    return None


def _get_frontend_url(request) -> str:
    # Prefer Origin/Host when FRONTEND_URL is missing or looks misconfigured.
    # This prevents Stripe cancel_url/success_url from pointing to a typo domain.
    origin = str(request.headers.get('Origin', '') or '').strip()
    configured = str(getattr(settings, 'FRONTEND_URL', '') or '').strip()
    if configured:
        if origin:
            try:
                from urllib.parse import urlsplit

                cfg = urlsplit(configured)
                org = urlsplit(origin)
                if cfg.scheme and cfg.netloc and org.scheme and org.netloc and cfg.netloc != org.netloc:
                    logger.warning(
                        'FRONTEND_URL host mismatch; using request Origin for redirects. '
                        'configured=%s origin=%s',
                        configured,
                        origin,
                    )
                    return origin.rstrip('/')
            except Exception:
                # If parsing fails, fall back to configured.
                pass

        return configured.rstrip('/')

    # Fallback for prod deployments where FRONTEND_URL may not be set.
    # Prefer Origin, then Referer, then request host.
    if origin:
        return origin.rstrip('/')

    referer = str(request.headers.get('Referer', '') or '').strip()
    if referer:
        # Keep only scheme+host if referer contains a path.
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(referer)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}".rstrip('/')
        except Exception:
            pass

    return f"{request.scheme}://{request.get_host()}".rstrip('/')


@api_view(['GET'])
@permission_classes([AllowAny])
def get_plans(request):
    """
    Get all active plans for pricing page

    GET /api/plans/
    """
    disabled = _paid_plans_disabled_response()
    if disabled is not None:
        return disabled

    plans = Plan.objects.filter(is_active=True).order_by('order', 'price')

    data = []
    for plan in plans:
        data.append({
            'id': plan.id,
            'name': plan.name,
            'display_name': plan.display_name,
            'description': plan.description,
            'price': float(plan.price),
            'price_yearly': float(plan.price_yearly) if plan.price_yearly is not None else None,
            'features': plan.features or [],
            'daily_scan_limit': plan.scans_per_day,
            'monthly_scan_limit': plan.scans_per_month,
            'concurrent_scans': plan.concurrent_scans,
            'storage_limit_mb': plan.storage_limit_mb,
            'retention_days': plan.retention_days,
            'allow_dangerous_tools': plan.allow_dangerous_tools,
            'allow_teams': plan.allow_teams,
            'max_team_members': plan.max_team_members,
            'allow_integrations': plan.allow_integrations,
            'max_integrations': plan.max_integrations,
            'is_popular': plan.is_popular,
        })

    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_subscription(request):
    """
    Get current user's subscription details with full billing info

    GET /api/subscriptions/current/
    """
    # When paid plans are disabled, return a synthetic enterprise plan so the
    # UI works and the scanner grants full detector access.
    if not bool(getattr(settings, 'PAID_PLANS_ENABLED', True)):
        return Response({
            'plan_name': 'Enterprise',
            'plan_id': None,
            'daily_scan_limit': 9999,
            'monthly_scan_limit': 9999,
            'concurrent_scans': 10,
            'storage_limit_mb': 10240,
            'retention_days': 365,
            'status': 'active',
            'scans_used_today': 0,
            'scans_used_this_month': 0,
            'current_period_start': None,
            'current_period_end': None,
            'cancel_at_period_end': False,
            'stripe_subscription_id': None,
            'stripe_customer_id': None,
            'plan': {
                'name': 'enterprise',
                'display_name': 'Enterprise',
                'description': 'Full access — billing disabled',
                'price': 0,
                'price_yearly': 0,
                'features': [],
                'is_popular': False,
            },
            'is_enterprise': True,
        })

    try:
        subscription = Subscription.objects.get(user=request.user, status='active')

        # Get plan features
        plan_features = subscription.plan.features or []

        data = {
            'id': subscription.id,
            'plan_name': subscription.plan.display_name,
            'plan_id': subscription.plan.id,
            'daily_scan_limit': subscription.plan.scans_per_day,
            'monthly_scan_limit': subscription.plan.scans_per_month,
            'concurrent_scans': subscription.plan.concurrent_scans,
            'storage_limit_mb': subscription.plan.storage_limit_mb,
            'retention_days': subscription.plan.retention_days,
            'status': subscription.status,
            'scans_used_today': subscription.scans_used_today,
            'scans_used_this_month': subscription.scans_used_this_month,
            'current_period_start': subscription.current_period_start,
            'current_period_end': subscription.current_period_end,
            'cancel_at_period_end': subscription.cancel_at_period_end,
            'stripe_subscription_id': subscription.stripe_subscription_id,
            'stripe_customer_id': subscription.stripe_customer_id,
            'plan': {
                'name': subscription.plan.name,
                'display_name': subscription.plan.display_name,
                'description': subscription.plan.description,
                'price': float(subscription.plan.price),
                'price_yearly': (
                    float(subscription.plan.price_yearly)
                    if subscription.plan.price_yearly is not None
                    else None
                ),
                'features': plan_features,
                'is_popular': subscription.plan.is_popular,
            },
            # Check if user is enterprise customer (safe check to avoid DB errors)
            'is_enterprise': subscription.plan.name == 'enterprise',
        }

        return Response(data)

    except Subscription.DoesNotExist:
        # Return free plan defaults
        try:
            free_plan = Plan.objects.get(name='free')
            return Response({
                'plan_name': 'Free',
                'plan_id': free_plan.id,
                'daily_scan_limit': free_plan.scans_per_day,
                'monthly_scan_limit': free_plan.scans_per_month,
                'status': 'active',
                'scans_used_today': 0,
                'scans_used_this_month': 0,
                'plan': {
                    'name': 'free',
                    'display_name': 'Free',
                    'price': 0,
                    'price_yearly': 0,
                    'features': free_plan.features or [],
                },
                'is_enterprise': False,
            })
        except Plan.DoesNotExist:
            return Response({'error': 'No plan found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_subscription(request):
    """
    Cancel user's subscription

    POST /api/subscriptions/cancel/
    Body: { "immediate": false }  // true = cancel now, false = cancel at period end
    """
    disabled = _paid_plans_disabled_response()
    if disabled is not None:
        return disabled

    try:
        subscription = Subscription.objects.get(user=request.user, status='active')
    except Subscription.DoesNotExist:
        return Response({'error': 'No active subscription found'}, status=status.HTTP_404_NOT_FOUND)

    # Check if already cancelled
    if subscription.cancel_at_period_end:
        return Response({'error': 'Subscription already scheduled for cancellation'},
                        status=status.HTTP_400_BAD_REQUEST)

    immediate = request.data.get('immediate', False)

    # If free plan or no Stripe subscription, just mark as cancelled
    if not subscription.stripe_subscription_id or subscription.plan.price == 0:
        subscription.status = 'cancelled'
        subscription.save()
        return Response({
            'message': 'Subscription cancelled',
            'cancel_at_period_end': False,
        })

    # Cancel Stripe subscription
    try:
        StripeService.cancel_subscription(
            subscription.stripe_subscription_id,
            at_period_end=not immediate
        )

        if immediate:
            subscription.status = 'cancelled'
            subscription.cancel_at_period_end = False
        else:
            subscription.cancel_at_period_end = True

        subscription.save()

        return Response({
            'message': 'Subscription cancelled successfully',
            'cancel_at_period_end': subscription.cancel_at_period_end,
            'current_period_end': subscription.current_period_end,
        })
    except Exception as e:
        logger.error(f'Failed to cancel subscription: {str(e)}')
        return Response({'error': 'Failed to cancel subscription'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_plan(request):
    """
    Upgrade from Free to Pro plan only

    POST /api/subscriptions/change-plan/
    Body: { "new_plan_id": 2 }
    """
    disabled = _paid_plans_disabled_response()
    if disabled is not None:
        return disabled

    new_plan_id = request.data.get('new_plan_id')
    billing_interval = request.data.get('billing_interval', 'month')

    if not new_plan_id:
        return Response({'error': 'new_plan_id is required'}, status=status.HTTP_400_BAD_REQUEST)

    billing_interval = str(billing_interval or 'month').strip().lower()
    if billing_interval in {'monthly'}:
        billing_interval = 'month'
    if billing_interval in {'yearly', 'annual', 'annually'}:
        billing_interval = 'year'
    if billing_interval not in {'month', 'year'}:
        return Response(
            {'error': 'billing_interval must be "month" or "year"'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        new_plan = Plan.objects.get(id=new_plan_id, is_active=True)
    except Plan.DoesNotExist:
        return Response({'error': 'Plan not found'}, status=status.HTTP_404_NOT_FOUND)

    # ONLY allow Free → Pro upgrade
    if new_plan.name != 'pro':
        return Response({
            'error': 'Invalid plan change',
            'message': 'Only upgrade from Free to Pro is available. For Enterprise, contact sales.',
            'redirect_url': '/register-enterprise' if new_plan.name == 'enterprise' else None
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        subscription = Subscription.objects.get(user=request.user, status='active')

        # Block if already on Pro or Enterprise
        if subscription.plan.name != 'free':
            current_plan = subscription.plan.display_name
            return Response(
                {
                    'error': 'Plan change not allowed',
                    'message': (
                        f'You are currently on {current_plan} plan. '
                        'Downgrades are not supported. Contact support for assistance.'
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Allow Free → Pro upgrade only
        if subscription.plan.id == new_plan_id:
            return Response({'error': 'Already on this plan'}, status=status.HTTP_400_BAD_REQUEST)

    except Subscription.DoesNotExist:
        # No subscription - allow only Pro plan creation
        pass

    # Create checkout for Pro plan
    try:
        frontend_url = _get_frontend_url(request)
        checkout_session = StripeService.create_checkout_session(
            user=request.user,
            plan=new_plan,
            success_url=f"{frontend_url}/subscription",
            cancel_url=f"{frontend_url}/subscription",
            billing_interval=billing_interval,
        )
        return Response({
            'checkout_url': checkout_session.url,
            'requires_payment': True,
        })
    except ImproperlyConfigured as e:
        logger.error('Stripe misconfigured during checkout creation: %s', e)
        return Response(
            {
                'error': 'Billing is temporarily unavailable',
                'message': 'Stripe is not configured on the server. Please contact support.',
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    except Exception:
        # Stripe SDK raises stripe.error.StripeError, but keep this broad to avoid leaking details.
        logger.exception(
            'Failed to create checkout session (user_id=%s plan_id=%s plan_name=%s interval=%s)',
            getattr(request.user, 'id', None),
            getattr(new_plan, 'id', None),
            getattr(new_plan, 'name', None),
            billing_interval,
        )
        return Response(
            {
                'error': 'Failed to create checkout session',
                'message': 'Please try again later or contact support.',
            },
            status=status.HTTP_502_BAD_GATEWAY,
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reactivate_subscription(request):
    """
    Reactivate a cancelled subscription (cancel the cancellation)

    POST /api/subscriptions/reactivate/
    """
    disabled = _paid_plans_disabled_response()
    if disabled is not None:
        return disabled

    try:
        subscription = Subscription.objects.get(user=request.user)
    except Subscription.DoesNotExist:
        return Response({'error': 'No subscription found'}, status=status.HTTP_404_NOT_FOUND)

    if not subscription.cancel_at_period_end:
        return Response({'error': 'Subscription is not scheduled for cancellation'}, status=status.HTTP_400_BAD_REQUEST)

    if subscription.stripe_subscription_id:
        try:
            # Update Stripe subscription to not cancel
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY
            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=False
            )

            subscription.cancel_at_period_end = False
            subscription.save()

            return Response({
                'message': 'Subscription reactivated successfully',
            })
        except Exception as e:
            logger.error(f'Failed to reactivate subscription: {str(e)}')
            return Response({'error': 'Failed to reactivate subscription'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        subscription.cancel_at_period_end = False
        subscription.status = 'active'
        subscription.save()

        return Response({
            'message': 'Subscription reactivated successfully',
        })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def sync_subscription(request):
    """
    Sync subscription with Stripe after successful checkout

    POST /api/subscriptions/sync/
    Body: { "session_id": "cs_test_..." }
    """
    disabled = _paid_plans_disabled_response()
    if disabled is not None:
        return disabled

    import stripe

    stripe_key = str(getattr(settings, 'STRIPE_SECRET_KEY', '') or '').strip()
    if not stripe_key:
        return Response(
            {
                'error': 'Billing is temporarily unavailable',
                'message': 'Stripe is not configured on the server. Please contact support.',
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    stripe.api_key = stripe_key

    session_id = request.data.get('session_id')
    if not session_id:
        return Response({'error': 'session_id required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Retrieve checkout session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)

        if session.payment_status != 'paid':
            return Response({'error': 'Payment not completed'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle checkout completion (update subscription)
        StripeService.handle_checkout_completed(session)

        return Response({
            'message': 'Subscription synced successfully',
            'status': 'success'
        })

    except stripe.error.StripeError as e:
        logger.error(f'Stripe error during sync: {str(e)}')
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f'Failed to sync subscription: {str(e)}')
        return Response({'error': 'Failed to sync subscription'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upgrade_to_enterprise(request):
    """
    Upgrade existing user (Free/Pro) to Enterprise plan
    Requires company information

    POST /api/subscriptions/upgrade-to-enterprise/
    """
    disabled = _paid_plans_disabled_response()
    if disabled is not None:
        return disabled

    from .models import EnterpriseCustomer, Plan

    # Check if user already has Enterprise
    existing = EnterpriseCustomer.objects.filter(user=request.user).first()
    if existing and existing.is_active:
        return Response({'error': 'Already an Enterprise customer'}, status=status.HTTP_400_BAD_REQUEST)

    # Get Enterprise plan
    try:
        enterprise_plan = Plan.objects.get(name='enterprise', is_active=True)
    except Plan.DoesNotExist:
        return Response({'error': 'Enterprise plan not available'}, status=status.HTTP_404_NOT_FOUND)

    # Extract company data
    company_data = {
        'company_name': request.data.get('company_name'),
        'vat_number': request.data.get('vat_number', ''),
        'registration_number': request.data.get('registration_number', ''),
        'billing_address': request.data.get('billing_address'),
        'billing_city': request.data.get('billing_city'),
        'billing_country': request.data.get('billing_country', 'Bulgaria'),
        'billing_zip': request.data.get('billing_zip', ''),
        'billing_email': request.data.get('billing_email', request.user.email),
        'billing_phone': request.data.get('billing_phone', ''),
        'accounting_contact_name': request.data.get('accounting_contact_name', ''),
        'accounting_contact_email': request.data.get('accounting_contact_email', ''),
        'payment_terms': request.data.get('payment_terms', 'net_30'),
    }

    # Validate required fields
    if not company_data['company_name'] or not company_data['billing_address'] or not company_data['billing_city']:
        return Response({'error': 'Company name, billing address, and billing city are required'},
                        status=status.HTTP_400_BAD_REQUEST)

    try:
        # Get or update subscription
        subscription, created = Subscription.objects.get_or_create(
            user=request.user,
            defaults={'plan': enterprise_plan, 'status': 'pending'}
        )

        if not created:
            # Mark as pending until payment
            subscription.plan = enterprise_plan
            subscription.status = 'pending'
            subscription.cancel_at_period_end = False

        # Create or update EnterpriseCustomer
        if existing:
            # Reactivate existing
            for key, value in company_data.items():
                setattr(existing, key, value)
            existing.is_active = True
            existing.subscription = subscription
            existing.save()
            enterprise_customer = existing
        else:
            # Create new
            enterprise_customer = EnterpriseCustomer.objects.create(
                user=request.user,
                subscription=subscription,
                is_active=False,  # Will activate after payment
                **company_data
            )

        # Create Payment Intent instead of Checkout Session
        payment_intent = StripeService.create_payment_intent(
            user=request.user,
            plan=enterprise_plan,
            metadata={
                'subscription_id': subscription.id,
                'enterprise_customer_id': enterprise_customer.id,
            }
        )

        logger.info(f"Created Enterprise upgrade payment intent for user {request.user.email}")

        return Response({
            'message': 'Enterprise registration initiated',
            'client_secret': payment_intent.client_secret,
            'requires_payment': True,
        })

    except Exception as e:
        logger.error(f'Failed to upgrade to Enterprise: {str(e)}')
        return Response({'error': 'Failed to create Enterprise upgrade'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
