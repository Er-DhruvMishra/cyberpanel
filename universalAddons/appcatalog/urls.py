from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-appcatalog')]
for _name in ('sites', 'catalogue', 'check', 'install', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-appcatalog-' + _name))
