from django.urls import path

from . import views

urlpatterns = [
    path('', views.page, name='ua-emaildebug'),
    path('ajax/context', views.context, name='ua-emaildebug-context'),
    path('ajax/dns', views.dns, name='ua-emaildebug-dns'),
    path('ajax/ports', views.ports, name='ua-emaildebug-ports'),
    path('ajax/logs', views.logs, name='ua-emaildebug-logs'),
    path('ajax/queue', views.queue, name='ua-emaildebug-queue'),
    path('ajax/spam', views.spam, name='ua-emaildebug-spam'),
    path('ajax/send', views.send, name='ua-emaildebug-send'),
]
