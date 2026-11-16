from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-dnstools')]
for _name in ('zones', 'dnssec_status', 'dnssec_enable', 'dnssec_disable', 'dnssec_rectify', 'templates',
              'template_save', 'template_preview', 'apply_preview', 'apply'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-dnstools-' + _name))
