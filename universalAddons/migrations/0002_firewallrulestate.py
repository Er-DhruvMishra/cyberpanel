# Additive: creates one new table (ua_firewall_rule_state) and changes no existing one.
# Firewall rules are referenced by integer id (no foreign key): the firewall app has no
# migration files in this tree, so a migration cannot depend on it.
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('universalAddons', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='FirewallRuleState',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('rule_id', models.IntegerField(unique=True)),
                ('enabled', models.BooleanField(default=True)),
                ('disabled_at', models.DateTimeField(blank=True, null=True)),
                ('updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'ua_firewall_rule_state',
            },
        ),
    ]
