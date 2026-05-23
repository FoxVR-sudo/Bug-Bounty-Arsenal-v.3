from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0005_user_two_factor_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="teammember",
            name="use_custom_permissions",
            field=models.BooleanField(default=False),
        ),
    ]
