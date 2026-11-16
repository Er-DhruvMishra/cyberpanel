"""One row per free subdomain handed out: who owns it, which site uses it, where its DNS lives."""
from django.db import models


class FreeSubdomain(models.Model):
    label = models.CharField(max_length=40)
    base = models.CharField(max_length=200)
    fqdn = models.CharField(max_length=255, unique=True)
    # The site that uses the name (a website or a child domain). One free subdomain per site.
    site = models.CharField(max_length=255, unique=True)
    # Plain ids, not foreign keys: a removed account must not silently drop the DNS bookkeeping.
    owner_id = models.IntegerField()
    owner_name = models.CharField(max_length=50, default='')
    created_by_id = models.IntegerField()
    provider = models.CharField(max_length=20)
    # Provider-specific record references (JSON), e.g. record ids, needed to delete exactly what we created.
    refs = models.TextField(default='{}')
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'ic_free_subdomain'
        ordering = ('fqdn',)
        unique_together = (('label', 'base'),)

    def __str__(self):
        return self.fqdn
