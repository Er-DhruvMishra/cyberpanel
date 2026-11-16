from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-sitetools')]
for _name in ('sites', 'overview', 'redirects', 'hotlink', 'errorpage_get', 'errorpage_save', 'errorpage_remove',
              'protect', 'unprotect', 'user_set', 'user_remove', 'clone', 'push', 'restore', 'job'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-sitetools-' + _name))
