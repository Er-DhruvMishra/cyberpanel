from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-appsvc')]
for _name in ('overview', 'logs', 'preflight', 'install', 'remove', 'configure', 'revert', 'control', 'reveal', 'job',
              'remove_preview', 'pg_create', 'disk', 'runtimes', 'oracle_db_check'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-appsvc-' + _name))
