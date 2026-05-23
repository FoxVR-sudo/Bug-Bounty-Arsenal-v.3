from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0010_user_phone_verification_code_hashed'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pendingsignup',
            name='phone',
            field=models.CharField(blank=True, max_length=20),
        ),
    ]
