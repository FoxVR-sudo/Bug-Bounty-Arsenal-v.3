# Generated manually 2026-05-08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0011_pendingsignup_phone_blank"),
    ]

    operations = [
        migrations.RenameIndex(
            model_name="pendingemailsignup",
            new_name="pending_ema_email_24fea6_idx",
            old_name="pending_em_email_2a9f2b_idx",
        ),
        migrations.RenameIndex(
            model_name="pendingemailsignup",
            new_name="pending_ema_expires_2dcc19_idx",
            old_name="pending_em_expires_5e0a21_idx",
        ),
        migrations.AlterField(
            model_name="user",
            name="phone_verification_code",
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="scan_start_hourly_limit",
            field=models.PositiveIntegerField(blank=True, help_text="Max scan starts per hour. Null = global default.", null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="scan_stop_hourly_limit",
            field=models.PositiveIntegerField(blank=True, help_text="Max scan stops per hour. Null = global default.", null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="export_hourly_limit",
            field=models.PositiveIntegerField(blank=True, help_text="Max exports per hour. Null = global default.", null=True),
        ),
    ]
