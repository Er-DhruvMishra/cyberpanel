from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-apache')]
for _name in ('overview', 'preview', 'apply', 'install', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-apache-' + _name))
