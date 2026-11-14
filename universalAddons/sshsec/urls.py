from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-sshsec')]
for _name in ('overview', 'analyze', 'audit', 'blocklist', 'block', 'unblock', 'enable_jail', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-sshsec-' + _name))
