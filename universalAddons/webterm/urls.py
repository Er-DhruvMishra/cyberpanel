from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-webterm')]
for _name in ('ticket', 'status', 'setup', 'teardown', 'policy'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-webterm-' + _name))
