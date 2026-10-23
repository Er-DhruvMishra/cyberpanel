from django.urls import include, path

from . import views

urlpatterns = [
    path('', views.hub, name='ua-hub'),
    path('email-debugger/', include('universalAddons.emaildebug.urls')),
    path('root-file-manager/', include('universalAddons.rootfm.urls')),
    path('rspamd/', include('universalAddons.rspamd.urls')),
    path('ssl/', include('universalAddons.sslv2.urls')),
    path('backup/', include('universalAddons.backupv2.urls')),
    path('wordpress/', include('universalAddons.wordpress.urls')),
    path('htaccess/', include('universalAddons.htaccess.urls')),
]
