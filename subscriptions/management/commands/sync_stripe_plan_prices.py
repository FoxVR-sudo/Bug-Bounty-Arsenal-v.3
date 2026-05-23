from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Optional

import stripe
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from subscriptions.models import Plan


@dataclass(frozen=True)
class StripePriceInfo:
    price_id: str
    currency: str
    interval: str
    unit_amount_decimal: Decimal


def _ensure_stripe_configured() -> None:
    secret_key = str(getattr(settings, 'STRIPE_SECRET_KEY', '') or '').strip()
    if not secret_key:
        raise CommandError('STRIPE_SECRET_KEY is missing; cannot sync from Stripe')
    stripe.api_key = secret_key


def _parse_unit_amount_to_decimal(price_obj) -> Decimal:
    # Stripe returns either unit_amount (int cents) or unit_amount_decimal (string)
    if getattr(price_obj, 'unit_amount', None) is not None:
        return (Decimal(int(price_obj.unit_amount)) / Decimal('100')).quantize(Decimal('0.01'))

    unit_amount_decimal = getattr(price_obj, 'unit_amount_decimal', None)
    if unit_amount_decimal is None:
        raise CommandError(f'Stripe price {price_obj.id} has no unit_amount')

    return (Decimal(str(unit_amount_decimal)) / Decimal('100')).quantize(Decimal('0.01'))


def _fetch_and_validate_price(price_id: str, *, expected_interval: str) -> StripePriceInfo:
    try:
        price_obj = stripe.Price.retrieve(price_id)
    except stripe.error.StripeError as exc:
        raise CommandError(f'Failed to retrieve Stripe Price {price_id}: {exc.user_message or str(exc)}') from exc

    currency = str(getattr(price_obj, 'currency', '') or '').lower()
    if currency != 'usd':
        raise CommandError(f'Stripe Price {price_id} currency must be usd, got {currency!r}')

    price_type = str(getattr(price_obj, 'type', '') or '').lower()
    if price_type != 'recurring':
        raise CommandError(f'Stripe Price {price_id} must be recurring, got {price_type!r}')

    recurring = getattr(price_obj, 'recurring', None)
    interval = str(getattr(recurring, 'interval', '') or '').lower()
    if interval != expected_interval:
        raise CommandError(
            f'Stripe Price {price_id} must have interval {expected_interval!r}, got {interval!r}'
        )

    unit_amount_decimal = _parse_unit_amount_to_decimal(price_obj)

    return StripePriceInfo(
        price_id=price_id,
        currency=currency,
        interval=interval,
        unit_amount_decimal=unit_amount_decimal,
    )


class Command(BaseCommand):
    help = (
        'One-way sync Plan.price/Plan.price_yearly from Stripe Price IDs.\n'
        'Enforces USD-only and recurring intervals month/year.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--plan',
            dest='plan',
            default=None,
            help='Optional plan name to sync (e.g. pro). If omitted, syncs all active plans.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would change without saving to DB.',
        )
        parser.add_argument(
            '--no-monthly',
            action='store_true',
            help='Do not update Plan.price from stripe_price_id_monthly.',
        )
        parser.add_argument(
            '--no-yearly',
            action='store_true',
            help='Do not update Plan.price_yearly from stripe_price_id_yearly.',
        )

    def handle(self, *args, **options):
        _ensure_stripe_configured()

        plan_filter: Optional[str] = options.get('plan')
        dry_run: bool = bool(options.get('dry_run'))
        update_monthly: bool = not bool(options.get('no_monthly'))
        update_yearly: bool = not bool(options.get('no_yearly'))

        plans = Plan.objects.filter(is_active=True)
        if plan_filter:
            plans = plans.filter(name=plan_filter)

        if not plans.exists():
            raise CommandError('No matching active plans found')

        changed = 0
        skipped = 0

        for plan in plans.order_by('order', 'price'):
            monthly_id = str(getattr(plan, 'stripe_price_id_monthly', '') or '').strip()
            yearly_id = str(getattr(plan, 'stripe_price_id_yearly', '') or '').strip()

            if plan.price == 0 and not monthly_id and not yearly_id:
                skipped += 1
                self.stdout.write(f'- {plan.name}: skipped (free/no Stripe price IDs)')
                continue

            updates = {}

            if update_monthly and monthly_id:
                monthly = _fetch_and_validate_price(monthly_id, expected_interval='month')
                if plan.price != monthly.unit_amount_decimal:
                    updates['price'] = monthly.unit_amount_decimal

            if update_yearly and yearly_id:
                yearly = _fetch_and_validate_price(yearly_id, expected_interval='year')
                if plan.price_yearly != yearly.unit_amount_decimal:
                    updates['price_yearly'] = yearly.unit_amount_decimal

            if not updates:
                skipped += 1
                self.stdout.write(f'- {plan.name}: no changes')
                continue

            changed += 1
            self.stdout.write(f'- {plan.name}: {updates}')

            if not dry_run:
                Plan.objects.filter(pk=plan.pk).update(**updates)

        self.stdout.write(self.style.SUCCESS(f'Done. changed={changed} skipped={skipped} dry_run={dry_run}'))
