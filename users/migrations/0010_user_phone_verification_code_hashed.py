from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_pending_email_signup'),
    ]

    operations = [
        # Increase field size to hold Django password hashes (~128-200 chars)
        migrations.AlterField(
            model_name='user',
            name='phone_verification_code',
            field=models.CharField(
                blank=True,
                max_length=200,
                null=True,
                help_text='Hashed phone verification code (Django PBKDF2)',
            ),
        ),
    ]
