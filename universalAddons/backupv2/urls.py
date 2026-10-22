from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-backupv2')]
for _name in ('overview', 'save_repo', 'export_key', 'ssh_key', 'save_policy', 'delete_policy', 'run_now',
              'snapshots', 'ls', 'restore', 'check', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-backupv2-' + _name))
