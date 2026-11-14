from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-storage')]
for _name in ('scan', 'clean', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-storage-' + _name))
