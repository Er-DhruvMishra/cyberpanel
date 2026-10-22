from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-rspamd')]
for _name in ('detect', 'plan', 'filtering', 'apply', 'install', 'migrate_dkim', 'stats', 'log', 'learn', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-rspamd-' + _name))
