"""Provisioning API state: personal API tokens, single sign-on tickets, account suspensions.

Accounts are referenced by integer id (no foreign keys): loginSystem has no migrations, so a
migration here cannot depend on it.
"""
from django.db import models


class ApiToken(models.Model):
    """A named API token of one panel account. Only a SHA-256 digest of the secret is stored."""
    owner_id = models.IntegerField(db_index=True)
    name = models.CharField(max_length=64)
    key_id = models.CharField(max_length=24, unique=True)          # public part, shown in lists
    token_hash = models.CharField(max_length=64)                    # sha256 hex of the secret part
    scopes = models.CharField(max_length=100, default='read')       # comma separated
    allowed_ips = models.TextField(blank=True, default='')          # newline separated IPs/CIDRs
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by_id = models.IntegerField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.CharField(max_length=64, blank=True, default='')
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by_id = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ('-created_at', '-id')

    def scope_list(self):
        return [s for s in (self.scopes or '').split(',') if s]

    def ip_list(self):
        return [line.strip() for line in (self.allowed_ips or '').splitlines() if line.strip()]


class SsoTicket(models.Model):
    """A single-use login ticket. Only a SHA-256 digest of the ticket is stored."""
    ticket_hash = models.CharField(max_length=64, unique=True)
    account_id = models.IntegerField(db_index=True)
    issued_by_id = models.IntegerField()
    token_id = models.IntegerField(null=True, blank=True)
    redirect = models.CharField(max_length=200, default='/base/')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    used_ip = models.CharField(max_length=64, blank=True, default='')


class AccountSuspension(models.Model):
    """Which sites an account-level suspension took down, so unsuspend restores only those."""
    account_id = models.IntegerField(unique=True)
    parent_account_id = models.IntegerField(null=True, blank=True, db_index=True)  # reseller cascade
    sites = models.TextField(default='[]')        # JSON list of domains this suspension suspended
    reason = models.CharField(max_length=200, blank=True, default='')
    suspended_by_id = models.IntegerField()
    suspended_at = models.DateTimeField(auto_now_add=True)
