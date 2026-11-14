from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-emaillimits')]
for _name in ('overview', 'detail', 'save_mailbox', 'apply_all', 'refresh', 'save_domain', 'health', 'repair_cron',
              'policy'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-emaillimits-' + _name))
