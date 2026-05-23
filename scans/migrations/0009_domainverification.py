from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0008_vulnerability_confidence_cvss_score'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='DomainVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(help_text='Apex domain, e.g. example.com (no scheme, no path)', max_length=253)),
                ('token', models.CharField(max_length=64, unique=True)),
                ('status', models.CharField(
                    choices=[('pending', 'Pending'), ('verified', 'Verified'), ('failed', 'Failed')],
                    default='pending',
                    max_length=10,
                )),
                ('verified_at', models.DateTimeField(blank=True, null=True)),
                ('last_check_error', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='domain_verifications',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'db_table': 'domain_verifications',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddConstraint(
            model_name='domainverification',
            constraint=models.UniqueConstraint(fields=['user', 'domain'], name='unique_user_domain'),
        ),
        migrations.AddIndex(
            model_name='domainverification',
            index=models.Index(fields=['user', 'status'], name='domainverif_user_status_idx'),
        ),
        migrations.AddIndex(
            model_name='domainverification',
            index=models.Index(fields=['domain', 'status'], name='domainverif_domain_status_idx'),
        ),
    ]
