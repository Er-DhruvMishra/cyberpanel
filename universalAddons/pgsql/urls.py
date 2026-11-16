from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-pgsql'),
               path('download', views.download, name='ua-pgsql-download'),
               path('restore', views.restore, name='ua-pgsql-restore'),
               path('adminer-login', views.adminer_login, name='ua-pgsql-adminer-login')]
for _name in ('overview', 'create_db', 'drop_db', 'create_role', 'drop_role', 'reset_password', 'grant', 'revoke',
              'backups', 'backup', 'delete_backup', 'job', 'adminer_install', 'adminer_remove'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-pgsql-' + _name))
