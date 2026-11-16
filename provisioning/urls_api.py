from django.urls import path

from . import api_views

urlpatterns = [
    path('verify', api_views.verify, name='icApiVerify'),
    path('accounts/list', api_views.list_accounts, name='icApiListAccounts'),
    path('accounts/info', api_views.account_info, name='icApiAccountInfo'),
    path('accounts/usage', api_views.account_usage, name='icApiAccountUsage'),
    path('accounts/create', api_views.create_account, name='icApiCreateAccount'),
    path('accounts/suspend', api_views.suspend_account, name='icApiSuspendAccount'),
    path('accounts/unsuspend', api_views.unsuspend_account, name='icApiUnsuspendAccount'),
    path('accounts/terminate', api_views.terminate_account, name='icApiTerminateAccount'),
    path('accounts/password', api_views.change_password, name='icApiChangePassword'),
    path('accounts/package', api_views.change_package, name='icApiChangePackage'),
    path('packages/list', api_views.list_packages, name='icApiListPackages'),
    path('sso', api_views.create_sso, name='icApiSso'),
    path('sso/redeem', api_views.redeem_sso, name='icSsoRedeem'),
]
