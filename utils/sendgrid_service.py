"""
Email Service
Handles all email sending via Django email backend (Resend/SMTP/etc.)
"""
import logging
from typing import Optional
from urllib.parse import urlsplit

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.html import strip_tags


logger = logging.getLogger(__name__)


class SendGridService:
    """Email sending service (uses Django email backend - Resend, SMTP, etc.)"""

    def __init__(self):
        self.from_email = (
            str(getattr(settings, 'SENDGRID_FROM_EMAIL', '') or getattr(settings, 'EMAIL_FROM_EMAIL', '') or '').strip()
            or 'noreply@bugbounty-arsenal.net'
        )
        self.from_name = (
            str(getattr(settings, 'SENDGRID_FROM_NAME', '') or getattr(settings, 'EMAIL_FROM_NAME', '') or '').strip()
            or 'BugBounty Arsenal'
        )

        # Treat unit tests like development mode even if DEBUG=False.
        self._dev_mode = bool(getattr(settings, 'DEBUG', False) or getattr(settings, 'RUNNING_TESTS', False))

        backend = str(getattr(settings, 'EMAIL_BACKEND', '') or '').strip()
        self._backend_enabled = (
            'anymail' in backend
            or ('smtp' in backend.lower() and bool(str(getattr(settings, 'EMAIL_HOST', '') or '').strip()))
        )

        if not self._backend_enabled and not self._dev_mode:
            logger.error('Email provider not configured; email sending is disabled in production.')

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        to_name: Optional[str] = None
    ) -> bool:
        """
        Send email via the configured Django email backend.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email body
            text_content: Plain text fallback (optional)
            to_name: Recipient name (optional)

        Returns:
            True if sent successfully, False otherwise
        """
        if self._backend_enabled:
            try:
                from_email = f"{self.from_name} <{self.from_email}>" if self.from_name else self.from_email
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body=text_content or '',
                    from_email=from_email,
                    to=[to_email],
                )
                if html_content:
                    msg.attach_alternative(html_content, 'text/html')
                msg.send()
                logger.info('Email sent successfully to %s', to_email)
                return True
            except Exception as e:
                import traceback
                logger.error('Failed to send email to %s: %s', to_email, str(e))
                logger.debug('Full traceback: %s', traceback.format_exc())
                return False

        # Development fallback: print to console.
        if self._dev_mode:
            print('\n' + '=' * 70)
            print('📧 EMAIL (Console Output - no email provider configured)')
            print('=' * 70)
            print(f'From: {self.from_name} <{self.from_email}>')
            print(f'To: {to_name or ""} <{to_email}>')
            print(f'Subject: {subject}')
            print('-' * 70)
            print(html_content)
            print('=' * 70 + '\n')
            return True

        logger.error('Attempted to send email without an email provider configured')
        return False

    def _resolve_frontend_base_url(self, absolute_url: Optional[str] = None) -> str:
        frontend_base_url = str(getattr(settings, 'FRONTEND_URL', '') or '').strip().rstrip('/')

        if absolute_url:
            try:
                parts = urlsplit(absolute_url)
                if parts.scheme and parts.netloc:
                    frontend_base_url = f'{parts.scheme}://{parts.netloc}'.rstrip('/')
            except Exception:
                pass

        return frontend_base_url or 'http://localhost:3000'

    def _render_text_template(self, template_name: str, context: dict, html_content: str) -> str:
        try:
            return render_to_string(f'emails/{template_name}.txt', context).strip()
        except TemplateDoesNotExist:
            return strip_tags(html_content)

    def _send_template_email(
        self,
        *,
        template_name: str,
        to_email: str,
        to_name: str,
        subject: str,
        context: dict,
        absolute_url: Optional[str] = None,
    ) -> bool:
        frontend_base_url = self._resolve_frontend_base_url(absolute_url)

        render_context = dict(context)
        render_context.setdefault('subject', subject)
        render_context.setdefault('user_email', to_email)
        render_context.setdefault('current_year', timezone.now().year)
        render_context.setdefault('frontend_base_url', frontend_base_url)
        render_context.setdefault('dashboard_url', f'{frontend_base_url}/dashboard')
        render_context.setdefault('docs_url', f'{frontend_base_url}/docs')
        render_context.setdefault('contact_url', f'{frontend_base_url}/contact')

        html_content = render_to_string(f'emails/{template_name}.html', render_context)
        text_content = self._render_text_template(template_name, render_context, html_content)
        return self.send_email(to_email, subject, html_content, text_content, to_name)

    def send_verification_email(self, user_email: str, user_name: str, verification_url: str) -> bool:
        """Send email verification link"""
        subject = 'Verify your email address'
        return self._send_template_email(
            template_name='verify_email',
            to_email=user_email,
            to_name=user_name,
            subject=subject,
            absolute_url=verification_url,
            context={
                'user_name': user_name,
                'verification_url': verification_url,
                'message_preview': 'Confirm this email address to activate your account.',
            },
        )

    def send_password_reset_email(self, user_email: str, user_name: str, reset_url: str) -> bool:
        """Send password reset link"""
        subject = 'Reset Your BugBounty Arsenal Password'
        return self._send_template_email(
            template_name='password_reset',
            to_email=user_email,
            to_name=user_name,
            subject=subject,
            absolute_url=reset_url,
            context={
                'user_name': user_name,
                'reset_url': reset_url,
                'message_preview': 'Use the secure link below to choose a new password for your account.',
            },
        )

    def send_scan_complete_email(self, user_email: str, user_name: str, scan_data: dict) -> bool:
        """Send scan completion notification"""
        subject = f'Scan Complete: {scan_data.get("target", "Target")}'

        vulnerabilities = scan_data.get('vulnerabilities_found', 0)
        severity_color = '#ef4444' if vulnerabilities > 0 else '#10b981'

        status_message_html = (
            "<p style='color: #ef4444; font-weight: bold;'>"
            "⚠️ Critical vulnerabilities detected! Review immediately."
            "</p>"
            if vulnerabilities > 0
            else (
                "<p style='color: #10b981; font-weight: bold;'>"
                "✅ No critical vulnerabilities found."
                "</p>"
            )
        )

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }}
                .stat-card {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    border: 2px solid #e5e7eb;
                }}
                .stat-value {{ font-size: 32px; font-weight: bold; color: {severity_color}; }}
                .stat-label {{ font-size: 14px; color: #6b7280; margin-top: 5px; }}
                .button {{
                    display: inline-block;
                    padding: 15px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Scan Complete</h1>
                </div>
                <div class="content">
                    <h2>Hello, {user_name}</h2>
                    <p>Your security scan has finished running.</p>

                    <div style="background: #e0e7ff; padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <strong>Target:</strong> {scan_data.get('target', 'N/A')}<br>
                        <strong>Scan Type:</strong> {scan_data.get('scan_type', 'N/A')}<br>
                        <strong>Duration:</strong> {scan_data.get('duration', 'N/A')}
                    </div>

                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-value">{vulnerabilities}</div>
                            <div class="stat-label">Vulnerabilities Found</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{scan_data.get('detectors_run', 0)}</div>
                            <div class="stat-label">Detectors Run</div>
                        </div>
                    </div>

                    <div style="text-align: center;">
                        <a href="{scan_data.get('results_url', '#')}" class="button">View Detailed Results</a>
                    </div>

                    {status_message_html}
                </div>
                <div class="footer">
                    <p>&copy; 2026 BugBounty Arsenal. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        return self.send_email(user_email, subject, html_content, None, user_name)

    def send_welcome_email(self, user_email: str, user_name: str) -> bool:
        """Send welcome email after successful verification"""
        subject = 'Your account is ready'

        return self._send_template_email(
            template_name='welcome',
            to_email=user_email,
            to_name=user_name,
            subject=subject,
            context={
                'user_name': user_name,
                'plan_name': 'Free',
                'message_preview': 'Your email is verified and your account is ready.',
            },
        )

    def send_plan_upgraded_email(self, user_email: str, user_name: str, plan_name: str) -> bool:
        subject = f'Your plan is now {plan_name.title()} 🎉'

        frontend_url = str(getattr(settings, 'FRONTEND_URL', '') or '').strip().rstrip('/')
        if not frontend_url:
            frontend_url = 'http://localhost:3000'

        support_email = str(getattr(settings, 'SUPPORT_EMAIL', '') or '').strip() or 'support@example.com'

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{
                    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .button {{
                    display: inline-block;
                    padding: 15px 30px;
                    background: #10b981;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Plan upgraded</h1>
                </div>
                <div class="content">
                    <h2>Hi {user_name},</h2>
                    <p>Your subscription has been upgraded to <strong>{plan_name.title()}</strong>.</p>

                    <div style="text-align: center;">
                        <a href="{frontend_url}/dashboard" class="button">Go to Dashboard</a>
                    </div>

                    <p style="margin-top: 30px;">
                        If you have any questions, reply to this email or contact us at {support_email}.
                    </p>
                </div>
                <div class="footer">
                    <p>&copy; 2026 BugBounty Arsenal. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        return self.send_email(user_email, subject, html_content, None, user_name)


# Backward-compatible global instance for the configured email backend.
sendgrid_service = SendGridService()
