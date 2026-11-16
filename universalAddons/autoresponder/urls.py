from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-autoresponder')]
for _name in ('mailboxes', 'get', 'save', 'health'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-autoresponder-' + _name))
