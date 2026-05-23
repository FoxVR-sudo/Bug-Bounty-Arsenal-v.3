import subscriptions.stripe_service as stripe_service


def test_create_checkout_session_prefers_stripe_price_id(
    settings,
    test_user,
    user_subscription,
    pro_plan,
    monkeypatch,
):
    settings.STRIPE_SECRET_KEY = "sk_test_123"

    pro_plan.stripe_price_id_monthly = "price_month_123"
    pro_plan.stripe_price_id_yearly = "price_year_123"
    pro_plan.stripe_product_id = "prod_123"
    pro_plan.save()

    monkeypatch.setattr(
        stripe_service.StripeService,
        "create_customer",
        staticmethod(lambda user, email=None: "cus_123"),
    )

    captured = {}

    def fake_session_create(**kwargs):
        captured.update(kwargs)

        class FakeSession:
            id = "cs_test_123"
            url = "https://example.com/checkout"

        return FakeSession()

    monkeypatch.setattr(stripe_service.stripe.checkout.Session, "create", fake_session_create)

    session = stripe_service.StripeService.create_checkout_session(
        user=test_user,
        plan=pro_plan,
        success_url="https://example.com/success",
        cancel_url="https://example.com/cancel",
    )

    assert session.id == "cs_test_123"
    assert captured["line_items"][0]["price"] == "price_month_123"
    assert "price_data" not in captured["line_items"][0]


def test_create_checkout_session_uses_yearly_price_id_when_requested(
    settings,
    test_user,
    user_subscription,
    pro_plan,
    monkeypatch,
):
    settings.STRIPE_SECRET_KEY = "sk_test_123"

    pro_plan.stripe_price_id_monthly = "price_month_123"
    pro_plan.stripe_price_id_yearly = "price_year_123"
    pro_plan.stripe_product_id = "prod_123"
    pro_plan.save()

    monkeypatch.setattr(
        stripe_service.StripeService,
        "create_customer",
        staticmethod(lambda user, email=None: "cus_123"),
    )

    captured = {}

    def fake_session_create(**kwargs):
        captured.update(kwargs)

        class FakeSession:
            id = "cs_test_123"
            url = "https://example.com/checkout"

        return FakeSession()

    monkeypatch.setattr(stripe_service.stripe.checkout.Session, "create", fake_session_create)

    session = stripe_service.StripeService.create_checkout_session(
        user=test_user,
        plan=pro_plan,
        success_url="https://example.com/success",
        cancel_url="https://example.com/cancel",
        billing_interval="year",
    )

    assert session.id == "cs_test_123"
    assert captured["line_items"][0]["price"] == "price_year_123"
    assert "price_data" not in captured["line_items"][0]
