from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-htaccess')]
for _name in ('overview', 'preview', 'enable', 'disable'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-htaccess-' + _name))
