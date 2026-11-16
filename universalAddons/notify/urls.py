from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-notify')]
for _name in ('overview', 'channel_save', 'channel_delete', 'channel_test', 'preferences'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-notify-' + _name))
