from django.urls import path

from . import views

urlpatterns = [path('', views.page, name='ua-visitstats'), path('report', views.report, name='ua-visitstats-report')]
for _name in ('overview', 'generate', 'options', 'job', 'check_available', 'install'):
    urlpatterns.append(path('ajax/' + _name, getattr(views, _name), name='ua-visitstats-' + _name))
