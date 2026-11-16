# Additive: creates three new tables and changes no existing one. Accounts are referenced by
# integer id (no foreign keys), because loginSystem has no migrations and a migration cannot
# depend on it.
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='ApiToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('owner_id', models.IntegerField(db_index=True)),
                ('name', models.CharField(max_length=64)),
                ('key_id', models.CharField(max_length=24, unique=True)),
                ('token_hash', models.CharField(max_length=64)),
                ('scopes', models.CharField(default='read', max_length=100)),
                ('allowed_ips', models.TextField(blank=True, default='')),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by_id', models.IntegerField(blank=True, null=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('last_used_ip', models.CharField(blank=True, default='', max_length=64)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('revoked_by_id', models.IntegerField(blank=True, null=True)),
            ],
            options={'ordering': ('-created_at', '-id')},
        ),
        migrations.CreateModel(
            name='SsoTicket',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ticket_hash', models.CharField(max_length=64, unique=True)),
                ('account_id', models.IntegerField(db_index=True)),
                ('issued_by_id', models.IntegerField()),
                ('token_id', models.IntegerField(blank=True, null=True)),
                ('redirect', models.CharField(default='/base/', max_length=200)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('used_at', models.DateTimeField(blank=True, null=True)),
                ('used_ip', models.CharField(blank=True, default='', max_length=64)),
            ],
        ),
        migrations.CreateModel(
            name='AccountSuspension',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('account_id', models.IntegerField(unique=True)),
                ('parent_account_id', models.IntegerField(blank=True, db_index=True, null=True)),
                ('sites', models.TextField(default='[]')),
                ('reason', models.CharField(blank=True, default='', max_length=200)),
                ('suspended_by_id', models.IntegerField()),
                ('suspended_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
