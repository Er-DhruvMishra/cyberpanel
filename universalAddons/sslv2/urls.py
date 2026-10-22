from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-sslv2')]
for _name in ('inventory', 'check', 'issue', 'job', 'monitor'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-sslv2-' + _name))
