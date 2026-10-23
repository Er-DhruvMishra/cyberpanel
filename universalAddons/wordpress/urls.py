from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-wordpress')]
for _name in ('sites', 'info', 'item', 'flag', 'autoupdates', 'hardening', 'fix', 'performance', 'login', 'snapshots',
              'update', 'snapshot', 'rollback', 'clone', 'push', 'install', 'wpcli', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-wordpress-' + _name))
