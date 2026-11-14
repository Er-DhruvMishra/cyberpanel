from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-mssql')]
for _name in ('overview', 'install', 'service', 'job', 'databases', 'create', 'reset', 'drop'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-mssql-' + _name))
