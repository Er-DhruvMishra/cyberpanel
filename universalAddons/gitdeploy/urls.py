from django.urls import path

from . import views

urlpatterns = [
    path('', views.page, name='ua-gitdeploy'),
    path('hook/<str:hook_id>/', views.hook, name='ua-gitdeploy-hook'),
]
for _name in ('sites', 'status', 'save', 'key', 'secret', 'disconnect', 'deploy', 'rollback', 'log', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-gitdeploy-' + _name))
