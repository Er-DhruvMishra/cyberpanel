from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-freesub')]
for _name in ('overview', 'test', 'save', 'forget', 'release', 'check'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-freesub-' + _name))
