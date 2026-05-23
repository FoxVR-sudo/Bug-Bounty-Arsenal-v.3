import pytest


@pytest.mark.unit
@pytest.mark.django_db
def test_contact_page_uses_configured_support_email(django_client, settings):
    settings.SUPPORT_EMAIL = 'helpdesk@example.test'
    settings.SALES_EMAIL = 'sales@example.test'
    settings.SECURITY_EMAIL = 'security@example.test'
    settings.PRESS_EMAIL = 'press@example.test'

    res = django_client.get('/contact/')
    assert res.status_code == 200

    content = res.content.decode('utf-8')
    assert 'helpdesk@example.test' in content
    assert 'sales@example.test' in content
    assert 'security@example.test' in content
    assert 'press@example.test' in content
