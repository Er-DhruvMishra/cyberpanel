from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-smtprelay')]
for _name in ('overview', 'save', 'disable', 'test'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-smtprelay-' + _name))
