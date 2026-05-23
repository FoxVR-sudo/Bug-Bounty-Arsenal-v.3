from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0012_add_per_user_rate_limits'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='last_seen_city',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='user',
            name='last_seen_country',
            field=models.CharField(blank=True, help_text='ISO country code', max_length=2),
        ),
    ]
