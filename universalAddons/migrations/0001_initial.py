# Additive: creates two new tables and changes no existing one. Accounts and websites are
# referenced by integer id (no foreign keys), because loginSystem and websiteFunctions have no
# migrations and a migration cannot depend on them.
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='BackupDestination',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('owner_id', models.IntegerField(db_index=True)),
                ('name', models.CharField(max_length=64)),
                ('provider', models.CharField(max_length=32)),
                ('public_config', models.TextField(default='{}')),
                ('connected', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('last_test', models.DateTimeField(blank=True, null=True)),
                ('last_test_ok', models.BooleanField(blank=True, null=True)),
                ('last_test_message', models.CharField(blank=True, default='', max_length=500)),
            ],
            options={
                'db_table': 'ua_backup_destination',
                'ordering': ('owner_id', 'name'),
                'unique_together': {('owner_id', 'name')},
            },
        ),
        migrations.CreateModel(
            name='DestinationBackupJob',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('website_id', models.IntegerField(db_index=True)),
                ('created_by_id', models.IntegerField()),
                ('schedule', models.CharField(choices=[('manual', 'manual'), ('hourly', 'hourly'), ('daily', 'daily'),
                                                       ('weekly', 'weekly')], default='daily', max_length=10)),
                ('hour', models.PositiveSmallIntegerField(default=2)),
                ('keep_daily', models.PositiveSmallIntegerField(default=7)),
                ('keep_weekly', models.PositiveSmallIntegerField(default=4)),
                ('keep_monthly', models.PositiveSmallIntegerField(default=6)),
                ('enabled', models.BooleanField(default=True)),
                ('last_run', models.DateTimeField(blank=True, null=True)),
                ('last_status', models.CharField(blank=True, default='', max_length=500)),
                ('destination', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='jobs',
                                                  to='universalAddons.backupdestination')),
            ],
            options={
                'db_table': 'ua_destination_backup_job',
                'ordering': ('website_id', 'destination_id'),
                'unique_together': {('website_id', 'destination')},
            },
        ),
    ]
