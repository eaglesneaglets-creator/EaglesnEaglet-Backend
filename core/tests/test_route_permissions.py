"""Guard: manually-routed ViewSet actions must keep their @action kwargs.

``ViewSet.as_view({"post": "award"})`` silently ignores
``@action(permission_classes=[...])`` — only DRF routers merge an action's
kwargs into the view. That let any authenticated eaglet reach the Eagle-only
``/points/award/`` view (the service layer happened to catch it). This test
walks every URL and fails if a route drops an action's security kwargs.
"""
from django.urls import get_resolver
from django.urls.resolvers import URLResolver

SECURITY_KWARGS = ("permission_classes", "authentication_classes", "throttle_classes")


def _walk(patterns, prefix=""):
    for p in patterns:
        if isinstance(p, URLResolver):
            yield from _walk(p.url_patterns, prefix + str(p.pattern))
        else:
            yield prefix + str(p.pattern), p.callback


def test_no_route_drops_action_level_security_kwargs():
    dropped = []
    for route, callback in _walk(get_resolver().url_patterns):
        cls = getattr(callback, "cls", None)
        actions = getattr(callback, "actions", None)
        if not cls or not actions:
            continue
        initkwargs = getattr(callback, "initkwargs", {}) or {}
        for http_method, name in actions.items():
            action_kwargs = getattr(getattr(cls, name, None), "kwargs", None) or {}
            for key in SECURITY_KWARGS:
                if key in action_kwargs and initkwargs.get(key) != action_kwargs[key]:
                    dropped.append(f"{http_method.upper()} /{route} -> {cls.__name__}.{name} drops {key}")
    assert not dropped, "\n".join(dropped)
