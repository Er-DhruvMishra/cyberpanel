from django.urls import path

from . import views

urlpatterns = [
    path('', views.settings_page, name='icBranding'),
    path('fetch', views.fetch, name='icBrandingFetch'),
    path('save', views.save, name='icBrandingSave'),
    path('logo/upload', views.upload_logo, name='icBrandingLogoUpload'),
    path('logo/remove', views.remove_logo, name='icBrandingLogoRemove'),
    path('reset', views.reset, name='icBrandingReset'),
]
