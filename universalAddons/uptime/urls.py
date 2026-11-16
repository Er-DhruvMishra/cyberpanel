from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-uptime')]
for _name in ('overview', 'save', 'delete', 'detail', 'check_now'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-uptime-' + _name))
