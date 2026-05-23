from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_pending_signup'),
    ]

    operations = [
        migrations.CreateModel(
            name='PendingEmailSignup',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, serialize=False)),
                ('email', models.EmailField(unique=True, max_length=254, db_index=True)),
                ('password_hash', models.CharField(max_length=256)),
                ('first_name', models.CharField(max_length=100, blank=True)),
                ('middle_name', models.CharField(max_length=100, blank=True)),
                ('last_name', models.CharField(max_length=100, blank=True)),
                ('phone', models.CharField(max_length=20, blank=True)),
                ('address', models.TextField(blank=True)),
                ('accepted_documents', models.JSONField(default=dict, blank=True)),
                ('accepted_at', models.DateTimeField(null=True, blank=True)),
                ('ip_address', models.GenericIPAddressField(null=True, blank=True)),
                ('user_agent', models.TextField(blank=True)),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'pending_email_signups',
                'indexes': [
                    models.Index(fields=['email', 'created_at'], name='pending_em_email_2a9f2b_idx'),
                    models.Index(fields=['expires_at'], name='pending_em_expires_5e0a21_idx'),
                ],
            },
        ),
    ]