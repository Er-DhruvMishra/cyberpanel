"""Initialise Django inside root-side add-on processes that need the panel database."""
import os
import sys

_READY = False


def setup():
    global _READY
    if _READY:
        return
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CyberCP.settings')
    import django
    django.setup()
    _READY = True
