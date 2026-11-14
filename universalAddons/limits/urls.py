from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-limits')]
for _name in ('overview', 'save', 'preview', 'apply', 'du_scan', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-limits-' + _name))
