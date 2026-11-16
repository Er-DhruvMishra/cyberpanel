from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-apps')]
for _name in ('runtimes', 'runtime_install', 'runtime_uninstall', 'package_uninstall', 'policy', 'apps', 'save',
              'deploy', 'control', 'logs', 'delete', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-apps-' + _name))
