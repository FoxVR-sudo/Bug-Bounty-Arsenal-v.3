# SendGrid Email Integration Setup

## 📧 Overview

BugBounty Arsenal uses SendGrid for transactional emails:
- ✉️ Email verification
- 🔐 Password reset
- 👋 Welcome emails
- 📊 Scan completion notifications

## 🚀 Quick Setup

### 1. Get SendGrid API Key

1. Go to https://signup.sendgrid.com/ (Free tier: 100 emails/day)
2. Verify your email address
3. Navigate to Settings → API Keys
4. Click "Create API Key"
5. Choose "Full Access" (or "Restricted" with Mail Send permissions)
6. Copy the API key

### 2. Configure Environment

Add to your `.env` file or export:

```bash
export SENDGRID_API_KEY='<SENDGRID_API_KEY_PLACEHOLDER>'
export SENDGRID_FROM_EMAIL='noreply@yourdomain.com'
export SENDGRID_FROM_NAME='BugBounty Arsenal'
```

Or in `docker-compose.yml`:

```yaml
services:
  web:
    environment:
      - SENDGRID_API_KEY=<SENDGRID_API_KEY_PLACEHOLDER>
      - SENDGRID_FROM_EMAIL=noreply@bugbounty-arsenal.com
      - SENDGRID_FROM_NAME=BugBounty Arsenal
```

### 3. Verify Domain (Production Only)

For production emails, verify your domain:

1. Go to Settings → Sender Authentication
2. Click "Verify a Single Sender" (quick) or "Authenticate Your Domain" (better)
3. Follow DNS verification steps
4. Update `SENDGRID_FROM_EMAIL` to use verified domain

## 📝 API Endpoints

### Email Verification

```bash
# Request verification email
curl -X POST http://localhost:8001/api/auth/request-verification/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Verify email with token
curl -X POST http://localhost:8001/api/auth/verify-email/ \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "Mw",
    "token": "d1to12-f4ccc3faf3e1f6f3a0d562f81cf6dc64"
  }'
```

### Password Reset

```bash
# Request password reset
curl -X POST http://localhost:8001/api/auth/request-reset/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Reset password with token
curl -X POST http://localhost:8001/api/auth/reset-password/ \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "Mw",
    "token": "d1to12-f4ccc3faf3e1f6f3a0d562f81cf6dc64",
    "new_password": "NewSecurePass123!"
  }'
```

## 🎨 Email Templates

All emails use beautiful HTML templates with:
- Responsive design (mobile-friendly)
- Branded header with gradient
- Clear CTA buttons
- Security warnings
- Plain text fallback

### Email Types

1. **Verification Email**
   - Subject: "Verify Your BugBounty Arsenal Account"
   - Token expires in 24 hours
   - Includes verification link

2. **Password Reset**
   - Subject: "Reset Your BugBounty Arsenal Password"
   - Token expires in 1 hour
   - Security notice included

3. **Welcome Email**
   - Subject: "Welcome to BugBounty Arsenal! 🎯"
   - Sent after successful verification
   - Getting started guide

4. **Scan Complete**
   - Subject: "Scan Complete: {target}"
   - Vulnerability count and severity
   - Link to detailed results

## 🔧 Development Mode

Without SendGrid API key, emails print to console:

```
======================================================================
📧 EMAIL (Console Output - SendGrid not configured)
======================================================================
From: BugBounty Arsenal <noreply@bugbounty-arsenal.com>
To: User <user@example.com>
Subject: Verify Your BugBounty Arsenal Account
----------------------------------------------------------------------
[HTML content here]
======================================================================
```

Check Docker logs:
```bash
sudo docker logs bugbounty-web 2>&1 | grep -A 50 "EMAIL"
```

## 💰 SendGrid Pricing

- **Free Tier**: 100 emails/day (3,000/month)
- **Essentials**: $19.95/month for 50,000 emails
- **Pro**: $89.95/month for 100,000 emails

Free tier is perfect for development and small deployments!

## 🛡️ Security

- Tokens are cryptographically secure (Django's `default_token_generator`)
- Verification tokens expire after 24 hours
- Reset tokens expire after 1 hour
- Email lookup doesn't reveal if account exists (security best practice)
- All tokens are one-time use

## 🧪 Testing

### Test Email Sending

```python
from utils.sendgrid_service import sendgrid_service

# Test verification email
sendgrid_service.send_verification_email(
    user_email='test@example.com',
    user_name='Test User',
    verification_url='http://localhost:3000/verify-email/test/token/'
)

# Test password reset
sendgrid_service.send_password_reset_email(
    user_email='test@example.com',
    user_name='Test User',
    reset_url='http://localhost:3000/reset-password/test/token/'
)
```

### Monitor Email Delivery

SendGrid Dashboard shows:
- Delivery rate
- Open rate
- Click rate
- Bounces
- Spam reports

## 🐛 Troubleshooting

### Emails not sending

1. **Check API key**:
   ```bash
   echo $SENDGRID_API_KEY
   ```

2. **Check logs**:
   ```bash
   sudo docker logs bugbounty-web 2>&1 | tail -100
   ```

3. **Test API key**:
   ```python
   from sendgrid import SendGridAPIClient
   client = SendGridAPIClient('YOUR_API_KEY')
   # If this works, API key is valid
   ```

### Emails going to spam

1. Verify your domain (Settings → Sender Authentication)
2. Add SPF and DKIM records to DNS
3. Use a professional from_email (not @gmail.com)
4. Start with small volume and build reputation

### Rate limits

Free tier: 100 emails/day
- Batch verification emails
- Add rate limiting to endpoints
- Consider upgrading for production

## 📚 Resources

- [SendGrid Documentation](https://docs.sendgrid.com/)
- [Python SDK](https://github.com/sendgrid/sendgrid-python)
- [Email Best Practices](https://sendgrid.com/blog/email-best-practices/)
- [Deliverability Guide](https://sendgrid.com/resource/the-email-deliverability-guide/)

## 🔜 Roadmap

- [ ] Email templates customization in admin panel
- [ ] Email preferences (user can opt-out of notifications)
- [ ] Email analytics dashboard
- [ ] Custom SMTP server support (alternative to SendGrid)
- [ ] Email queuing for bulk operations
- [ ] A/B testing for email templates

---

**Status**: ✅ Implemented and tested
**Production Ready**: Yes (with API key)
**Last Updated**: January 3, 2026
