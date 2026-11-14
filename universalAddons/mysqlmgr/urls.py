from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-mysqlmgr')]
for _name in ('status', 'databases', 'processes', 'kill', 'advise', 'apply', 'revert', 'check', 'restart', 'upgrade', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-mysqlmgr-' + _name))
