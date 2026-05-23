from __future__ import annotations

from collections import Counter
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Count
from django.utils import timezone

from users.models import LegalAcceptance, User


class Command(BaseCommand):
    help = "Audit signup spam indicators (counts, verification rate, top IPs/UAs/domains)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="How many days back to analyze (default: 30)",
        )
        parser.add_argument(
            "--top",
            type=int,
            default=20,
            help="Top N items to print for IPs/UAs/domains (default: 20)",
        )

    def handle(self, *args, **options):
        days: int = options["days"]
        top: int = options["top"]
        since = timezone.now() - timedelta(days=days)

        total = User.objects.count()
        total_since = User.objects.filter(created_at__gte=since).count()
        verified_total = User.objects.filter(is_verified=True).count()
        verified_since = User.objects.filter(is_verified=True, created_at__gte=since).count()

        self.stdout.write(f"USERS_TOTAL={total}")
        self.stdout.write(f"USERS_LAST_{days}D={total_since}")
        self.stdout.write(f"VERIFIED_TOTAL={verified_total}")
        self.stdout.write(f"VERIFIED_LAST_{days}D={verified_since}")

        self.stdout.write("\nSIGNUPS_BY_DAY (last %d days):" % days)
        by_day = (
            User.objects.filter(created_at__gte=since)
            .extra(select={"day": "date(created_at)"})
            .values("day")
            .annotate(c=Count("id"))
            .order_by("day")
        )
        for row in by_day:
            self.stdout.write(f"  {row['day']}: {row['c']}")

        # Email domains (best-effort, no full emails printed)
        self.stdout.write("\nTOP_EMAIL_DOMAINS:")
        domains = Counter()
        for email in User.objects.filter(created_at__gte=since).values_list("email", flat=True):
            try:
                domain = (email.split("@", 1)[1] if "@" in email else "").lower().strip()
            except Exception:
                domain = ""
            if domain:
                domains[domain] += 1
        for domain, count in domains.most_common(top):
            self.stdout.write(f"  {domain}: {count}")

        # Legal acceptance captures signup IP/UA
        qs = LegalAcceptance.objects.filter(event=LegalAcceptance.EVENT_SIGNUP, accepted_at__gte=since)

        self.stdout.write("\nTOP_SIGNUP_IPS (from LegalAcceptance):")
        for row in (
            qs.exclude(ip_address__isnull=True)
            .values("ip_address")
            .annotate(c=Count("id"))
            .order_by("-c")[:top]
        ):
            self.stdout.write(f"  {row['ip_address']}: {row['c']}")

        self.stdout.write("\nTOP_SIGNUP_USER_AGENTS (from LegalAcceptance):")
        for row in (
            qs.exclude(user_agent="")
            .values("user_agent")
            .annotate(c=Count("id"))
            .order_by("-c")[:top]
        ):
            ua = row["user_agent"]
            ua_short = (ua[:120] + "…") if len(ua) > 120 else ua
            self.stdout.write(f"  {row['c']}: {ua_short}")
