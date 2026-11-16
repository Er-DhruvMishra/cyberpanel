from django import template
from django.utils.html import conditional_escape
from django.utils.safestring import SafeData, mark_safe

from resellerBranding.service import DEFAULT_NAME

register = template.Library()


def _branded(value, brand):
    name = brand.get('name') if isinstance(brand, dict) else None
    text = value if isinstance(value, SafeData) else conditional_escape(value)
    if not name or name == DEFAULT_NAME:
        return mark_safe(text)
    return mark_safe(str(text).replace(DEFAULT_NAME, str(conditional_escape(name))))


@register.filter
def brand_title(value, brand=None):
    """Replace the IndiansCloud name in a page title with the reseller's brand name."""
    return _branded(value, brand)


class BrandTitleNode(template.Node):
    def __init__(self, nodelist):
        self.nodelist = nodelist

    def render(self, context):
        # A missing panel_brand (a render without context processors) means the default brand.
        return _branded(self.nodelist.render(context), context.get('panel_brand'))


@register.tag
def brandtitle(parser, token):
    """{% brandtitle %}...{% endbrandtitle %}: the enclosed title, with the reseller's brand name."""
    nodelist = parser.parse(('endbrandtitle',))
    parser.delete_first_token()
    return BrandTitleNode(nodelist)
