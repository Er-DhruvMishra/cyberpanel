from django.urls import path

from . import panel_views

urlpatterns = [
    path('', panel_views.tokens_page, name='icApiTokens'),
    path('list', panel_views.list_tokens, name='icApiTokensList'),
    path('create', panel_views.create_token, name='icApiTokensCreate'),
    path('revoke', panel_views.revoke_token, name='icApiTokensRevoke'),
]
