from .service import resolve


def branding_context(request):
    """``panel_brand``: name, title_suffix, logo_url, primary_color, support_url, support_email,
    is_default. The IndiansCloud default whenever no reseller branding applies."""
    return {'panel_brand': resolve(request)}
