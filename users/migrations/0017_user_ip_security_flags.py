from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0016_user_location_coordinates'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='last_seen_is_anonymous',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='last_seen_is_hosting',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='last_seen_is_proxy',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='last_seen_is_tor',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='last_seen_is_vpn',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_is_anonymous',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_is_hosting',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_is_proxy',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_is_tor',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_is_vpn',
            field=models.BooleanField(blank=True, null=True),
        ),
    ]