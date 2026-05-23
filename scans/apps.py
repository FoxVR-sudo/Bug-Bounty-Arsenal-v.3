from django.apps import AppConfig


class ScansConfig(AppConfig):
    name = 'scans'

    def ready(self):
        from . import signals  # noqa: F401
