from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-bans')]
for _name in ('overview', 'search', 'unban', 'ban', 'whitelist_add', 'whitelist_remove'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-bans-' + _name))
