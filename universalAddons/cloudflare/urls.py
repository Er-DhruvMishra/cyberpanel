from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-cloudflare')]
for _name in ('state', 'token_save', 'token_forget', 'token_verify', 'zones', 'overview', 'link', 'dns_list',
              'dns_save', 'dns_delete', 'dns_proxied', 'dns_import_preview', 'dns_import_apply', 'point_here',
              'purge', 'settings', 'setting_set', 'under_attack', 'rules', 'rule_add', 'rule_delete', 'analytics',
              'origin_cert', 'audit_log'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-cloudflare-' + _name))
