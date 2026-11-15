from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-mssql')]
for _name in ('overview', 'install', 'service', 'job', 'databases', 'create', 'reset', 'drop',
              'tables', 'columns', 'structure', 'rows', 'query', 'update_row', 'delete_row', 'insert_row', 'export'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-mssql-' + _name))
