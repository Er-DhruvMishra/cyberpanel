from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-sshsec')]
for _name in ('overview', 'analyze', 'audit', 'blocklist', 'block', 'unblock', 'enable_jail', 'job',
              'login_state', 'login_apply', 'login_confirm', 'login_revert',
              'keys_list', 'keys_add', 'keys_remove', 'keys_rotate', 'keys_generate'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-sshsec-' + _name))
