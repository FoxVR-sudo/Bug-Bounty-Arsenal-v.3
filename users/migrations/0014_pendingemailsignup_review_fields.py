# Generated manually 2026-05-11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_user_last_seen_location'),
    ]

    operations = [
        migrations.AddField(
            model_name='pendingemailsignup',
            name='bot_signals',
            field=models.JSONField(blank=True, default=list, help_text='Suspicious indicators collected during admin review.'),
        ),
        migrations.AddField(
            model_name='pendingemailsignup',
            name='is_bot_suspected',
            field=models.BooleanField(db_index=True, default=False, help_text='Exclude suspected automated signups from funnel metrics until reviewed.'),
        ),
        migrations.AddField(
            model_name='pendingemailsignup',
            name='reviewed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]