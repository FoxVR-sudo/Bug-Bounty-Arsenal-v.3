from django.urls import path
from .webhooks import stripe_webhook

urlpatterns = [
    path('', stripe_webhook, name='stripe-webhook'),
]
