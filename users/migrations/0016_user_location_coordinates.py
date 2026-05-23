from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0015_user_registration_and_last_seen_ip'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='last_seen_latitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='last_seen_longitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_latitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_longitude',
            field=models.FloatField(blank=True, null=True),
        ),
    ]