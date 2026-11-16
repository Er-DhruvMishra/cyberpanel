from django.urls import path

from . import views

# Mounted under /api/v2/brand/: the login page needs the logo before any session exists.
urlpatterns = [
    path('logo/<int:reseller_id>/<str:digest>', views.logo, name='icBrandLogo'),
]
