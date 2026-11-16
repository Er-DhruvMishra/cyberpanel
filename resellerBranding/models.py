"""White-label branding of one reseller account. The reseller is referenced by integer id (no
foreign key), because loginSystem has no migrations."""
from django.db import models


class ResellerBranding(models.Model):
    reseller_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=60)
    primary_color = models.CharField(max_length=7, blank=True, default='')
    support_url = models.CharField(max_length=200, blank=True, default='')
    support_email = models.CharField(max_length=100, blank=True, default='')
    hostname = models.CharField(max_length=253, unique=True, null=True, blank=True)
    logo_data = models.TextField(blank=True, default='')        # base64 of the validated file
    logo_mime = models.CharField(max_length=40, blank=True, default='')
    logo_hash = models.CharField(max_length=16, blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)
