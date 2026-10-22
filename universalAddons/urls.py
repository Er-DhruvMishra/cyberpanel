from django.urls import include, path

from . import views

urlpatterns = [
    path('', views.hub, name='ua-hub'),
    path('email-debugger/', include('universalAddons.emaildebug.urls')),
]
