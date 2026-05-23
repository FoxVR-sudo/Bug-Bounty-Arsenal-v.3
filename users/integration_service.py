from __future__ import annotations

import logging
from typing import Iterable, Optional

from django.db.models import Q

from users.integration_models import Integration
from users.team_models import TeamMember

logger = logging.getLogger(__name__)


def _get_user_team_ids(user_id: int) -> list[int]:
    return list(
        TeamMember.objects.filter(user_id=user_id, is_active=True)
        .values_list("team_id", flat=True)
        .distinct()
    )


def get_active_integrations_for_user(user_id: int) -> Iterable[Integration]:
    team_ids = _get_user_team_ids(user_id)
    q = Q(user_id=user_id)
    if team_ids:
        q |= Q(team_id__in=team_ids)
    return Integration.objects.filter(is_active=True).filter(q).order_by("-created_at")


def trigger_scan_event(*, scan, event_type: str, extra: Optional[dict] = None) -> None:
    data = {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "severity_counts": scan.severity_counts or {},
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
    if extra:
        data.update(extra)

    for integration in get_active_integrations_for_user(scan.user_id):
        try:
            integration.trigger(event_type, data)
        except Exception:
            logger.exception(
                "Integration trigger failed (id=%s type=%s event=%s)",
                integration.id,
                integration.integration_type,
                event_type,
            )
