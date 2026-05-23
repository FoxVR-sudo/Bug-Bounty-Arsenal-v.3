from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0014_pendingemailsignup_review_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='last_seen_ip',
            field=models.GenericIPAddressField(blank=True, help_text='Most recent client IP address', null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_city',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_country',
            field=models.CharField(blank=True, help_text='ISO country code', max_length=2),
        ),
        migrations.AddField(
            model_name='user',
            name='registration_ip',
            field=models.GenericIPAddressField(blank=True, help_text='IP address used at registration time', null=True),
        ),
    ]