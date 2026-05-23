"""
Billing views for Stripe integration and subscription management.
"""
import os

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from django.conf import settings
from usage.models import Plan
from usage.stripe_service import StripeService
import logging

logger = logging.getLogger(__name__)


def _get_frontend_url(request) -> str:
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
                        'FRONTEND_URL host mismatch; using request Origin for billing redirects. '
                        'configured=%s origin=%s',
                        configured,
                        origin,
                    )
                    return origin.rstrip('/')
            except Exception:
                pass

        return configured.rstrip('/')

    if origin:
        return origin.rstrip('/')

    referer = str(request.headers.get('Referer', '') or '').strip()
    if referer:
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(referer)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}".rstrip('/')
        except Exception:
            pass

    return f"{request.scheme}://{request.get_host()}".rstrip('/')


@extend_schema(
    summary="Create Stripe Checkout Session",
    description="Create a Stripe checkout session for subscribing to a plan",
    tags=["Billing"],
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_checkout_session(request):
    """Create Stripe checkout session for plan subscription"""

    if not bool(getattr(settings, 'PAID_PLANS_ENABLED', True)):
        payload = {'error': 'Billing is temporarily disabled.'}
        donate_url = str(getattr(settings, 'DONATE_URL', '') or '').strip()
        if donate_url:
            payload['donate_url'] = donate_url
        return Response(payload, status=status.HTTP_410_GONE)

    plan_id = request.data.get('plan_id')
    frontend_url = _get_frontend_url(request)
    success_url = request.data.get('success_url', f'{frontend_url}/dashboard')
    cancel_url = request.data.get('cancel_url', f'{frontend_url}/pricing')

    if not plan_id:
        return Response(
            {'error': 'plan_id is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        plan = Plan.objects.get(id=plan_id)

        # Check if Stripe is configured
        if not settings.STRIPE_SECRET_KEY or settings.STRIPE_SECRET_KEY == 'sk_test_...':
            # Test mode - return mock checkout
            logger.info(f"Test mode: mock checkout for plan {plan.name}")
            return Response({
                'checkout_url': f'{frontend_url}/mock-checkout?plan={plan_id}',
                'session_id': f'mock_session_{plan_id}',
                'message': 'Stripe not configured. Configure STRIPE_SECRET_KEY for real payments.'
            }, status=status.HTTP_200_OK)

        # Create real Stripe session
        session = StripeService.create_checkout_session(
            user=request.user,
            plan=plan,
            success_url=success_url,
            cancel_url=cancel_url
        )

        return Response({
            'checkout_url': session.url,
            'session_id': session.id
        }, status=status.HTTP_200_OK)

    except Plan.DoesNotExist:
        return Response(
            {'error': 'Plan not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Checkout error: {str(e)}")
        return Response(
            {'error': 'Failed to create checkout session'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Get Stripe Billing Portal URL",
    description="Get URL to Stripe billing portal for managing subscription",
    tags=["Billing"],
    responses={
        200: {
            'type': 'object',
            'properties': {
                'portal_url': {'type': 'string', 'description': 'Stripe portal URL'}
            }
        }
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def billing_portal(request):
    """
    Get Stripe billing portal URL for subscription management.

    In test mode, returns a mock portal URL.
    In production with Stripe configured, creates real portal session.
    """
    if not bool(getattr(settings, 'PAID_PLANS_ENABLED', True)):
        payload = {'error': 'Billing is temporarily disabled.'}
        donate_url = str(getattr(settings, 'DONATE_URL', '') or '').strip()
        if donate_url:
            payload['donate_url'] = donate_url
        return Response(payload, status=status.HTTP_410_GONE)

    from django.conf import settings

    stripe_key = settings.STRIPE_SECRET_KEY

    if not stripe_key or not stripe_key.startswith('sk_'):
        # Test mode - Stripe not configured
        return Response({
            'portal_url': '/mock-billing-portal',
            'message': 'Test mode: Stripe not configured'
        }, status=status.HTTP_200_OK)

    try:
        import stripe
        stripe.api_key = stripe_key

        # Get user's subscription
        from usage.models import Subscription
        subscription = Subscription.objects.filter(
            user=request.user,
            status='active'
        ).first()

        if not subscription or not subscription.stripe_customer_id:
            return Response(
                {'error': 'No active subscription with Stripe customer ID found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Create portal session
        session = stripe.billing_portal.Session.create(
            customer=subscription.stripe_customer_id,
            return_url=request.build_absolute_uri('/dashboard/'),
        )

        return Response({
            'portal_url': session.url
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error creating portal session: {e}")
        return Response(
            {'error': f'Failed to create portal session: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Buy Extra Scans",
    description="Purchase additional one-time scans",
    tags=["Billing"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'quantity': {'type': 'integer', 'description': 'Number of extra scans to buy'},
            },
            'required': ['quantity']
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'checkout_url': {'type': 'string'},
                'session_id': {'type': 'string'}
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def buy_extra_scans(request):
    """
    Buy extra one-time scans.

    In test mode, adds scans immediately.
    In production with Stripe configured, creates checkout session.
    """
    quantity = request.data.get('quantity', 1)

    if not isinstance(quantity, int) or quantity < 1:
        return Response(
            {'error': 'Invalid quantity. Must be a positive integer.'},
            status=status.HTTP_400_BAD_REQUEST
        )
        if not bool(getattr(settings, 'PAID_PLANS_ENABLED', True)):
            payload = {'error': 'Billing is temporarily disabled.'}
            donate_url = str(getattr(settings, 'DONATE_URL', '') or '').strip()
            if donate_url:
                payload['donate_url'] = donate_url
            return Response(payload, status=status.HTTP_410_GONE)

    stripe_key = os.getenv('STRIPE_SECRET_KEY', '')

    if not stripe_key or stripe_key.startswith('sk_test_') is False:
        # Test mode - add scans immediately
        from usage.models import Subscription
        subscription = Subscription.objects.filter(
            user=request.user,
            status='active'
        ).first()

        if subscription:
            subscription.extra_scans += quantity
            subscription.save()

        return Response({
            'message': f'Test mode: Added {quantity} extra scans',
            'extra_scans': subscription.extra_scans if subscription else quantity,
            'checkout_url': '/dashboard/',
        }, status=status.HTTP_200_OK)

    try:
        import stripe
        stripe.api_key = stripe_key

        # Price per extra scan (e.g., $5 per scan)
        price_per_scan = 500  # cents

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Extra Scans',
                        'description': f'{quantity} additional security scans',
                    },
                    'unit_amount': price_per_scan,
                },
                'quantity': quantity,
            }],
            mode='payment',
            success_url=request.build_absolute_uri('/dashboard/') + '?extra_scans=success',
            cancel_url=request.build_absolute_uri('/dashboard/'),
            customer_email=request.user.email,
            client_reference_id=str(request.user.id),
            metadata={
                'user_id': str(request.user.id),
                'type': 'extra_scans',
                'quantity': quantity,
            }
        )

        return Response({
            'checkout_url': session.url,
            'session_id': session.id
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error creating extra scans checkout: {e}")
        return Response(
            {'error': f'Failed to create checkout: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Change Subscription Tier",
    description="Upgrade or downgrade subscription plan",
    tags=["Billing"],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'new_plan_id': {'type': 'string', 'description': 'ID of the new plan'},
            },
            'required': ['new_plan_id']
        }
    },
    responses={
        200: {
            'type': 'object',
            'properties': {
                'message': {'type': 'string'},
                'new_plan': {'type': 'string'}
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_tier(request):
    """
    Change subscription to a different plan.

    In test mode, updates plan immediately.
    In production with Stripe configured, updates Stripe subscription.
    """
    new_plan_id = request.data.get('new_plan_id')

    if not new_plan_id:
        return Response(
            {'error': 'new_plan_id is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
        if not bool(getattr(settings, 'PAID_PLANS_ENABLED', True)):
            payload = {'error': 'Billing is temporarily disabled.'}
            donate_url = str(getattr(settings, 'DONATE_URL', '') or '').strip()
            if donate_url:
                payload['donate_url'] = donate_url
            return Response(payload, status=status.HTTP_410_GONE)

    try:
        from usage.models import Subscription, Plan

        # Get current subscription
        subscription = Subscription.objects.filter(
            user=request.user,
            status='active'
        ).first()

        if not subscription:
            return Response(
                {'error': 'No active subscription found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get new plan
        new_plan = Plan.objects.get(id=new_plan_id)

        stripe_key = os.getenv('STRIPE_SECRET_KEY', '')

        if not stripe_key or not subscription.stripe_subscription_id:
            # Test mode - update immediately
            old_plan = subscription.plan
            subscription.plan = new_plan
            subscription.save()

            return Response({
                'message': f'Test mode: Changed from {old_plan.name} to {new_plan.name}',
                'new_plan': new_plan.name
            }, status=status.HTTP_200_OK)

        # Production mode - update Stripe subscription
        import stripe
        stripe.api_key = stripe_key

        price_id = (new_plan.stripe_price_id_monthly or new_plan.stripe_price_id or '').strip()

        stripe.Subscription.modify(
            subscription.stripe_subscription_id,
            items=[{
                'id': subscription.stripe_subscription_id,
                'price': price_id,
            }],
            proration_behavior='create_prorations',
        )

        subscription.plan = new_plan
        subscription.save()

        return Response({
            'message': f'Subscription changed to {new_plan.name}',
            'new_plan': new_plan.name
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error changing tier: {e}")
        return Response(
            {'error': f'Failed to change tier: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
