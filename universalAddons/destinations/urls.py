from django.urls import path

from . import oauth, views

urlpatterns = [path('', views.page, name='ua-destinations')]
for _name in ('overview', 'save', 'rename', 'delete', 'test', 'usage', 'site_destinations', 'jobs', 'save_job',
              'delete_job', 'backup_now', 'snapshots', 'restore', 'job', 'oauth_clients', 'tools'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-destinations-' + _name))
urlpatterns += [
    path('oauth/<str:provider>/begin', oauth.begin, name='ua-destinations-oauth-begin'),
    path('oauth/<str:provider>/callback', oauth.callback, name='ua-destinations-oauth-callback'),
]
