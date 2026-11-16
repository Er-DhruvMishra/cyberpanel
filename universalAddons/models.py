"""Backup destinations: storage that a panel account connects for its own site backups.

A destination belongs to one panel account (``owner``, an Administrator row: administrator,
reseller or user). Only its public settings are stored here (provider, bucket, host, folder...).
Credentials and OAuth tokens live in a root-only store (see destinations/actions.py) and are
never returned to any browser, including an administrator's.
"""
from django.db import models

# loginSystem and websiteFunctions ship without migrations, and a migration may not depend on
# such apps, so accounts and websites are referenced by plain integer ids (no foreign keys).
# The properties below resolve them; a deleted account or site resolves to None.


def _admin(pk):
    from loginSystem.models import Administrator
    return Administrator.objects.filter(pk=pk).first()


def _website(pk):
    from websiteFunctions.models import Websites
    return Websites.objects.filter(pk=pk).first()


class BackupDestination(models.Model):
    id = models.AutoField(primary_key=True)
    owner_id = models.IntegerField(db_index=True)   # loginSystem.Administrator pk
    name = models.CharField(max_length=64)
    provider = models.CharField(max_length=32)
    # JSON of the provider's public fields only (never secrets).
    public_config = models.TextField(default='{}')
    # False while an OAuth destination waits for its first sign-in, or after a failed refresh.
    connected = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    last_test = models.DateTimeField(null=True, blank=True)
    last_test_ok = models.BooleanField(null=True, blank=True)
    last_test_message = models.CharField(max_length=500, default='', blank=True)

    class Meta:
        db_table = 'ua_backup_destination'
        unique_together = (('owner_id', 'name'),)
        ordering = ('owner_id', 'name')

    @property
    def owner(self):
        if getattr(self, '_owner', None) is None or self._owner.pk != self.owner_id:
            self._owner = _admin(self.owner_id)
        return self._owner

    def __str__(self):
        return '%s (%s)' % (self.name, self.provider)


class DestinationBackupJob(models.Model):
    """A site's backups to one destination: schedule and retention."""
    id = models.AutoField(primary_key=True)
    SCHEDULES = (('manual', 'manual'), ('hourly', 'hourly'), ('daily', 'daily'), ('weekly', 'weekly'))

    website_id = models.IntegerField(db_index=True)   # websiteFunctions.Websites pk
    destination = models.ForeignKey(BackupDestination, on_delete=models.CASCADE, related_name='jobs')
    # The account that set the job up; its rights are checked again on every run.
    created_by_id = models.IntegerField()   # loginSystem.Administrator pk
    schedule = models.CharField(max_length=10, choices=SCHEDULES, default='daily')
    hour = models.PositiveSmallIntegerField(default=2)
    keep_daily = models.PositiveSmallIntegerField(default=7)
    keep_weekly = models.PositiveSmallIntegerField(default=4)
    keep_monthly = models.PositiveSmallIntegerField(default=6)
    enabled = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=500, default='', blank=True)

    class Meta:
        db_table = 'ua_destination_backup_job'
        unique_together = (('website_id', 'destination'),)
        ordering = ('website_id', 'destination_id')

    @property
    def website(self):
        if getattr(self, '_website', None) is None or self._website.pk != self.website_id:
            self._website = _website(self.website_id)
        return self._website

    @property
    def created_by(self):
        return _admin(self.created_by_id)
