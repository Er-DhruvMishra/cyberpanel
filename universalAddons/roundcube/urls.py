from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-roundcube')]
for _name in ('overview', 'preflight', 'install', 'enable', 'disable', 'uninstall', 'upgrade', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-roundcube-' + _name))
