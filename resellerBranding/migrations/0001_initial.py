# Additive: creates one new table and changes no existing one. The reseller is referenced by
# integer id (no foreign key), because loginSystem has no migrations.
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='ResellerBranding',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reseller_id', models.IntegerField(unique=True)),
                ('name', models.CharField(max_length=60)),
                ('primary_color', models.CharField(blank=True, default='', max_length=7)),
                ('support_url', models.CharField(blank=True, default='', max_length=200)),
                ('support_email', models.CharField(blank=True, default='', max_length=100)),
                ('hostname', models.CharField(blank=True, max_length=253, null=True, unique=True)),
                ('logo_data', models.TextField(blank=True, default='')),
                ('logo_mime', models.CharField(blank=True, default='', max_length=40)),
                ('logo_hash', models.CharField(blank=True, default='', max_length=16)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
