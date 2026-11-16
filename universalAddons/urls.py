from django.urls import include, path

from . import views

urlpatterns = [
    path('', views.hub, name='ua-hub'),
    path('ajax/user-access', views.user_access, name='ua-hub-user-access'),
    path('email-debugger/', include('universalAddons.emaildebug.urls')),
    path('root-file-manager/', include('universalAddons.rootfm.urls')),
    path('rspamd/', include('universalAddons.rspamd.urls')),
    path('ssl/', include('universalAddons.sslv2.urls')),
    path('backup/', include('universalAddons.backupv2.urls')),
    path('destinations/', include('universalAddons.destinations.urls')),
    path('wordpress/', include('universalAddons.wordpress.urls')),
    path('htaccess/', include('universalAddons.htaccess.urls')),
    path('apps/', include('universalAddons.apps.urls')),
    path('mssql/', include('universalAddons.mssql.urls')),
    path('storage/', include('universalAddons.storage.urls')),
    path('email-limits/', include('universalAddons.emaillimits.urls')),
    path('ssh-security/', include('universalAddons.sshsec.urls')),
    path('smtp-relay/', include('universalAddons.smtprelay.urls')),
    path('mysql/', include('universalAddons.mysqlmgr.urls')),
    path('roundcube/', include('universalAddons.roundcube.urls')),
    path('limits/', include('universalAddons.limits.urls')),
    path('apache/', include('universalAddons.apache.urls')),
    path('terminal/', include('universalAddons.webterm.urls')),
    path('applications/', include('universalAddons.appsvc.urls')),
    path('free-subdomains/', include('freeSubdomains.urls')),
    path('cloudflare/', include('universalAddons.cloudflare.urls')),
    path('laravel/', include('universalAddons.laravel.urls')),
    path('git-deploy/', include('universalAddons.gitdeploy.urls')),
    path('site-tools/', include('universalAddons.sitetools.urls')),
]
