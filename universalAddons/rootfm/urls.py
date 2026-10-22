from django.urls import path

from . import views

urlpatterns = [
    path('', views.page, name='ua-rootfm'),
    path('download', views.download, name='ua-rootfm-download'),
    path('ajax/upload', views.upload, name='ua-rootfm-upload'),
]
for _name in ('listing', 'read', 'write', 'create', 'rename', 'copy', 'move', 'trash', 'list_trash', 'restore',
              'purge', 'chmod', 'chown', 'extract', 'compress', 'search', 'du', 'checksum'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-rootfm-' + _name))
