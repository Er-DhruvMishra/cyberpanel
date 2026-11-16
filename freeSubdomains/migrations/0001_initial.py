# Additive: creates one new table; changes no existing table.
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='FreeSubdomain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('label', models.CharField(max_length=40)),
                ('base', models.CharField(max_length=200)),
                ('fqdn', models.CharField(max_length=255, unique=True)),
                ('site', models.CharField(max_length=255, unique=True)),
                ('owner_id', models.IntegerField()),
                ('owner_name', models.CharField(default='', max_length=50)),
                ('created_by_id', models.IntegerField()),
                ('provider', models.CharField(max_length=20)),
                ('refs', models.TextField(default='{}')),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'ic_free_subdomain',
                'ordering': ('fqdn',),
                'unique_together': {('label', 'base')},
            },
        ),
    ]
