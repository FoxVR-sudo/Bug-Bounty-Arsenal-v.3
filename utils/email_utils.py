"""
Email utilities for BugBounty Arsenal
Handles sending templated emails for various events
"""
from django.core.mail import send_mail
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


def send_templated_email(template_name, context, recipient_email, subject):
    """
    Send an email using HTML template

    Args:
        template_name: Name of template file (without .html)
        context: Dictionary of variables for template
        recipient_email: Recipient's email address
        subject: Email subject line
    """
    try:
        # Add common context variables
        context.update({
            'user_email': recipient_email,
            'current_year': timezone.now().year,
            'subject': subject,
        })

        # Render HTML email
        html_message = render_to_string(f'emails/{template_name}.html', context)
        try:
            text_message = render_to_string(f'emails/{template_name}.txt', context).strip()
        except TemplateDoesNotExist:
            text_message = strip_tags(html_message)

        # Send email
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Email sent: {template_name} to {recipient_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email {template_name} to {recipient_email}: {e}")
        return False


def send_welcome_email(user):
    """Send welcome email to new user"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'user_email': user.email,
        'plan_name': user.current_plan or 'Free',
        'dashboard_url': f"{settings.FRONTEND_URL}/dashboard",
        'docs_url': f"{settings.FRONTEND_URL}/docs",
    }

    return send_templated_email(
        template_name='welcome',
        context=context,
        recipient_email=user.email,
        subject='Welcome to BugBounty Arsenal! 🎉'
    )


def send_verification_email(user, verification_code, verification_url):
    """Send email verification code"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'verification_code': verification_code,
        'verification_url': verification_url,
        'expiry_hours': 24,
    }

    return send_templated_email(
        template_name='verify_email',
        context=context,
        recipient_email=user.email,
        subject='Verify Your Email Address - BugBounty Arsenal'
    )


def send_plan_upgrade_email(user, old_plan, new_plan, billing_cycle, next_billing_date):
    """Send email when user upgrades plan"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'old_plan': old_plan,
        'new_plan': new_plan,
        'billing_cycle': billing_cycle,
        'next_billing_date': next_billing_date.strftime('%B %d, %Y'),
        'dashboard_url': f"{settings.FRONTEND_URL}/dashboard",
    }

    return send_templated_email(
        template_name='plan_upgraded',
        context=context,
        recipient_email=user.email,
        subject=f'Plan Upgraded to {new_plan}! 🎊'
    )


def send_plan_downgrade_email(user, old_plan, new_plan, effective_date):
    """Send email when user downgrades plan"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'old_plan': old_plan,
        'new_plan': new_plan,
        'effective_date': effective_date.strftime('%B %d, %Y'),
        'dashboard_url': f"{settings.FRONTEND_URL}/dashboard",
        'pricing_url': f"{settings.FRONTEND_URL}/pricing",
    }

    return send_templated_email(
        template_name='plan_downgraded',
        context=context,
        recipient_email=user.email,
        subject='Your Subscription Has Been Changed'
    )


def send_subscription_expiring_email(user, plan_name, expiration_date, days_remaining):
    """Send reminder email when subscription is expiring"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'plan_name': plan_name,
        'expiration_date': expiration_date.strftime('%B %d, %Y'),
        'days_remaining': days_remaining,
        'free_plan_scans': 10,  # From your plan settings
        'renew_url': f"{settings.FRONTEND_URL}/subscription",
        'manage_subscription_url': f"{settings.FRONTEND_URL}/subscription",
    }

    return send_templated_email(
        template_name='subscription_expiring',
        context=context,
        recipient_email=user.email,
        subject=f'Your Subscription Expires in {days_remaining} Days ⏰'
    )


def send_subscription_cancelled_email(user, plan_name, cancellation_date, access_until):
    """Send email when subscription is cancelled"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'plan_name': plan_name,
        'cancellation_date': cancellation_date.strftime('%B %d, %Y'),
        'access_until': access_until.strftime('%B %d, %Y'),
        'reactivate_url': f"{settings.FRONTEND_URL}/subscription",
        'feedback_url': f"{settings.FRONTEND_URL}/feedback",
    }

    return send_templated_email(
        template_name='subscription_cancelled',
        context=context,
        recipient_email=user.email,
        subject='Subscription Cancelled - BugBounty Arsenal'
    )


def send_payment_successful_email(
        user,
        amount,
        plan_name,
        invoice_number,
        payment_date,
        billing_period,
        next_billing_date,
        payment_method):
    """Send email after successful payment"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'amount': f"{amount:.2f}",
        'plan_name': plan_name,
        'invoice_number': invoice_number,
        'payment_date': payment_date.strftime('%B %d, %Y'),
        'billing_period': billing_period,
        'next_billing_date': next_billing_date.strftime('%B %d, %Y'),
        'payment_method': payment_method,
        'invoice_url': f"{settings.FRONTEND_URL}/invoices/{invoice_number}",
        'billing_history_url': f"{settings.FRONTEND_URL}/subscription/billing",
    }

    return send_templated_email(
        template_name='payment_successful',
        context=context,
        recipient_email=user.email,
        subject='Payment Received - BugBounty Arsenal'
    )


def send_payment_failed_email(user, amount, plan_name, failure_reason, retry_days, deadline_date):
    """Send email when payment fails"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'amount': f"{amount:.2f}",
        'plan_name': plan_name,
        'attempt_date': timezone.now().strftime('%B %d, %Y'),
        'failure_reason': failure_reason,
        'retry_days': retry_days,
        'deadline_date': deadline_date.strftime('%B %d, %Y'),
        'update_payment_url': f"{settings.FRONTEND_URL}/subscription/payment",
        'retry_payment_url': f"{settings.FRONTEND_URL}/subscription/retry-payment",
    }

    return send_templated_email(
        template_name='payment_failed',
        context=context,
        recipient_email=user.email,
        subject='Payment Failed - Action Required ⚠️'
    )


def send_password_reset_email(user, reset_code, reset_url):
    """Send password reset email"""
    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'reset_code': reset_code,
        'reset_url': reset_url,
        'expiry_hours': 24,
    }

    return send_templated_email(
        template_name='password_reset',
        context=context,
        recipient_email=user.email,
        subject='Reset Your Password - BugBounty Arsenal'
    )


def send_scan_complete_email(user, scan):
    """Send email when scan completes"""
    # Count vulnerabilities by severity
    vulnerabilities = scan.vulnerabilities.all()
    critical_count = vulnerabilities.filter(severity='critical').count()
    high_count = vulnerabilities.filter(severity='high').count()
    medium_count = vulnerabilities.filter(severity='medium').count()
    low_count = vulnerabilities.filter(severity='low').count()
    info_count = vulnerabilities.filter(severity='info').count()
    total_count = vulnerabilities.count()

    context = {
        'user_name': user.get_full_name() or user.email.split('@')[0],
        'target_url': scan.target_url,
        'categories': ', '.join([cat.display_name for cat in scan.categories.all()]),
        'duration': str(scan.duration) if hasattr(scan, 'duration') else 'N/A',
        'completion_date': scan.completed_at.strftime('%B %d, %Y at %I:%M %p') if scan.completed_at else 'N/A',
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'info_count': info_count,
        'total_count': total_count,
        'results_url': f"{settings.FRONTEND_URL}/scans/{scan.id}",
        'export_url': f"{settings.FRONTEND_URL}/scans/{scan.id}/export/pdf",
    }

    return send_templated_email(
        template_name='scan_complete',
        context=context,
        recipient_email=user.email,
        subject=f'Scan Complete: {scan.target_url} 🔍'
    )
