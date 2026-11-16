from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-laravel')]
for _name in ('apps', 'info', 'command', 'scheduler', 'worker', 'worker_logs', 'env', 'env_set', 'logs', 'public',
              'install', 'job', 'composer'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-laravel-' + _name))
