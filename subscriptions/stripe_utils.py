"""
Stripe payment integration utilities for subscription management.
"""

import stripe
from django.conf import settings
from django.core.exceptions import ValidationError
from .models import Subscription, Payment

stripe.api_key = str(getattr(settings, 'STRIPE_SECRET_KEY', '') or '').strip()


def create_checkout_session(user, plan, success_url, cancel_url, billing_interval: str = 'month'):
    """
    Create a Stripe Checkout session for subscription purchase.

    Args:
        user: User instance
        plan: Plan instance
        success_url: URL to redirect on success
        cancel_url: URL to redirect on cancel

    Returns:
        Checkout session object
    """
    try:
        interval = str(billing_interval or 'month').strip().lower()
        if interval in {'monthly'}:
            interval = 'month'
        if interval in {'yearly', 'annual', 'annually'}:
            interval = 'year'
        if interval not in {'month', 'year'}:
            raise ValidationError('billing_interval must be "month" or "year"')

        # Create or retrieve Stripe customer
        if not user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={
                    'user_id': user.id,
                    'username': user.username
                }
            )
            user.stripe_customer_id = customer.id
            user.save()
        else:
            customer = stripe.Customer.retrieve(user.stripe_customer_id)

        stripe_price_id_monthly = (getattr(plan, 'stripe_price_id_monthly', None) or '').strip()
        stripe_price_id_yearly = (getattr(plan, 'stripe_price_id_yearly', None) or '').strip()
        stripe_price_id_legacy = (getattr(plan, 'stripe_price_id', None) or '').strip()

        stripe_price_id = stripe_price_id_monthly
        if interval == 'year':
            stripe_price_id = stripe_price_id_yearly
        if not stripe_price_id and interval == 'month':
            stripe_price_id = stripe_price_id_legacy

        # Create checkout session
        session = stripe.checkout.Session.create(
            customer=customer.id,
            payment_method_types=['card'],
            line_items=[
                {
                    'price': stripe_price_id,
                    'quantity': 1,
                }
            ] if stripe_price_id else [
                {
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': plan.name,
                            'description': plan.description or f'{plan.name} subscription plan',
                        },
                        'unit_amount': int(plan.price * 100),  # Convert to cents
                        'recurring': {
                            'interval': interval,
                            'interval_count': 1,
                        },
                    },
                    'quantity': 1,
                }
            ],
            mode='subscription',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                'user_id': user.id,
                'plan_id': plan.id,
            }
        )

        return session

    except stripe.error.StripeError as e:
        raise ValidationError(f"Stripe error: {str(e)}")


def handle_checkout_session_completed(session):
    """
    Handle successful checkout session completion.
    Creates or updates subscription and records payment.

    Args:
        session: Stripe checkout session object
    """
    from users.models import User
    from .models import Plan

    user_id = int(session.metadata.get('user_id'))
    plan_id = int(session.metadata.get('plan_id'))

    user = User.objects.get(id=user_id)
    plan = Plan.objects.get(id=plan_id)

    # Get subscription details from Stripe
    stripe_subscription = stripe.Subscription.retrieve(session.subscription)

    # Create or update subscription
    subscription, created = Subscription.objects.update_or_create(
        user=user,
        defaults={
            'plan': plan,
            'status': 'active',
            'stripe_subscription_id': stripe_subscription.id,
            'current_period_start': stripe_subscription.current_period_start,
            'current_period_end': stripe_subscription.current_period_end,
        }
    )

    # Record payment
    Payment.objects.create(
        user=user,
        subscription=subscription,
        amount=plan.price,
        currency='usd',
        status='succeeded',
        stripe_payment_intent_id=session.payment_intent,
        stripe_invoice_id=stripe_subscription.latest_invoice,
    )

    return subscription


def handle_subscription_updated(stripe_subscription):
    """
    Handle subscription status updates from Stripe webhooks.

    Args:
        stripe_subscription: Stripe subscription object
    """
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=stripe_subscription.id
        )

        # Update subscription status
        subscription.status = stripe_subscription.status
        subscription.current_period_start = stripe_subscription.current_period_start
        subscription.current_period_end = stripe_subscription.current_period_end
        subscription.save()

        return subscription

    except Subscription.DoesNotExist:
        # Subscription not found, might be deleted
        return None


def handle_subscription_deleted(stripe_subscription):
    """
    Handle subscription cancellation from Stripe webhooks.

    Args:
        stripe_subscription: Stripe subscription object
    """
    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=stripe_subscription.id
        )
        subscription.status = 'canceled'
        subscription.save()
        return subscription

    except Subscription.DoesNotExist:
        return None


def handle_invoice_payment_succeeded(invoice):
    """
    Handle successful invoice payment from Stripe webhooks.

    Args:
        invoice: Stripe invoice object
    """

    try:
        subscription = Subscription.objects.get(
            stripe_subscription_id=invoice.subscription
        )

        # Record payment
        Payment.objects.create(
            user=subscription.user,
            subscription=subscription,
            amount=invoice.amount_paid / 100,  # Convert from cents
            currency=invoice.currency,
            status='succeeded',
            stripe_payment_intent_id=invoice.payment_intent,
            stripe_invoice_id=invoice.id,
        )

    except Subscription.DoesNotExist:
        pass


def cancel_subscription(subscription):
    """
    Cancel a subscription in Stripe.

    Args:
        subscription: Subscription instance

    Returns:
        Updated subscription
    """
    try:
        if subscription.stripe_subscription_id:
            stripe.Subscription.delete(
                subscription.stripe_subscription_id
            )
            subscription.status = 'canceled'
            subscription.save()

        return subscription

    except stripe.error.StripeError as e:
        raise ValidationError(f"Failed to cancel subscription: {str(e)}")


def create_portal_session(customer_id, return_url):
    """
    Create a Stripe Customer Portal session for subscription management.

    Args:
        customer_id: Stripe customer ID
        return_url: URL to return to after portal session

    Returns:
        Portal session URL
    """
    try:
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return session.url

    except stripe.error.StripeError as e:
        raise ValidationError(f"Failed to create portal session: {str(e)}")
