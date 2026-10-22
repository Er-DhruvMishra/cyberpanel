from plogical.httpProc import httpProc

from .registry import module_status


def hub(request):
    return httpProc(request, 'universalAddons/hub.html', {'modules': module_status()}, 'admin').render()
