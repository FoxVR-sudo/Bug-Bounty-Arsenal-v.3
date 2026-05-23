"""Landing page views for marketing and public pages"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from subscriptions.models import Plan


@require_http_methods(["GET"])
def landing_page(request):
    """Landing page view - marketing page for unauthenticated users"""
    plans = Plan.objects.filter(is_active=True).order_by('order')
    context = {
        'free_plan': plans.filter(name='free').first(),
        'pro_plan': plans.filter(name='pro').first(),
        'enterprise_plan': plans.filter(name='enterprise').first(),
    }
    return render(request, 'landing.html', context)


@require_http_methods(["GET"])
def login_page(request):
    """Login page view - renders login form"""
    return render(request, 'login.html')


@require_http_methods(["GET"])
def signup_page(request):
    """Signup page view - renders signup form"""
    return render(request, 'signup.html')


@require_http_methods(["GET"])
def pricing_page(request):
    """Pricing page view - renders pricing plans"""
    plans = Plan.objects.filter(is_active=True).order_by('order')
    context = {
        'free_plan': plans.filter(name='free').first(),
        'pro_plan': plans.filter(name='pro').first(),
        'enterprise_plan': plans.filter(name='enterprise').first(),
    }
    return render(request, 'pricing.html', context)


@login_required
@require_http_methods(["GET"])
def dashboard_page(request):
    """Dashboard page view - main app interface for authenticated users"""
    return render(request, 'dashboard.html')


# Footer pages
@require_http_methods(["GET"])
def docs_page(request):
    return render(request, 'docs.html')


@require_http_methods(["GET"])
def api_reference_page(request):
    return render(request, 'api_reference.html')


@require_http_methods(["GET"])
def about_page(request):
    return render(request, 'about.html')


@require_http_methods(["GET"])
def blog_page(request):
    return render(request, 'blog.html')


@require_http_methods(["GET"])
def careers_page(request):
    return render(request, 'careers.html')


@require_http_methods(["GET"])
def contact_page(request):
    from django.conf import settings

    return render(request, 'contact.html', {
        'support_email': getattr(settings, 'SUPPORT_EMAIL', ''),
        'sales_email': getattr(settings, 'SALES_EMAIL', ''),
        'security_email': getattr(settings, 'SECURITY_EMAIL', ''),
        'press_email': getattr(settings, 'PRESS_EMAIL', ''),
    })


@require_http_methods(["GET"])
def privacy_page(request):
    return render(request, 'privacy.html')


@require_http_methods(["GET"])
def terms_page(request):
    return render(request, 'terms.html')


@require_http_methods(["GET"])
def security_page(request):
    return render(request, 'security.html')


@require_http_methods(["GET"])
def compliance_page(request):
    return render(request, 'compliance.html')
