"""
Stripe webhook handlers for processing payment events.
"""

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.conf import settings
import stripe
import logging

from .stripe_service import StripeService

logger = logging.getLogger(__name__)
stripe.api_key = settings.STRIPE_SECRET_KEY


@csrf_exempt
@require_POST
def stripe_webhook(request):
    """
    Handle Stripe webhook events.

    Processes payment-related events from Stripe including:
    - checkout.session.completed: Payment successful
    - customer.subscription.updated: Subscription changed
    - customer.subscription.deleted: Subscription cancelled
    - invoice.payment_succeeded: Recurring payment successful
    - invoice.payment_failed: Payment failed
    """
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        logger.error(f"Stripe webhook: Invalid payload - {str(e)}")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Stripe webhook: Invalid signature - {str(e)}")
        return HttpResponse(status=400)

    # Handle the event
    event_type = event['type']
    event_data = event['data']['object']

    try:
        if event_type == 'checkout.session.completed':
            logger.info(f"Processing checkout.session.completed: {event_data['id']}")
            StripeService.handle_checkout_completed(event_data)

        elif event_type == 'payment_intent.succeeded':
            logger.info(f"Processing payment_intent.succeeded: {event_data['id']}")
            StripeService.handle_payment_intent_succeeded(event_data)

        elif event_type == 'customer.subscription.updated':
            logger.info(f"Processing subscription.updated: {event_data['id']}")
            StripeService.handle_subscription_updated(event_data)

        elif event_type == 'customer.subscription.deleted':
            logger.info(f"Processing subscription.deleted: {event_data['id']}")
            StripeService.handle_subscription_deleted(event_data)

        elif event_type == 'invoice.payment_succeeded':
            logger.info(f"Processing invoice.payment_succeeded: {event_data['id']}")
            StripeService.handle_invoice_paid(event_data)

        elif event_type == 'invoice.payment_failed':
            logger.warning(f"Payment failed for invoice: {event_data['id']}")
            StripeService.handle_invoice_payment_failed(event_data)

        else:
            logger.info(f"Unhandled webhook event type: {event_type}")

    except Exception as e:
        logger.error(f"Error processing webhook {event_type}: {str(e)}", exc_info=True)
        return HttpResponse(status=500)

    return HttpResponse(status=200)
