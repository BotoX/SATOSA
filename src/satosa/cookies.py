import http.cookies as _http_cookies


_http_cookies.Morsel._reserved["samesite"] = "SameSite"

SimpleCookie = _http_cookies.SimpleCookie


def parse_cookie(cookie):
    """
    Return a dictionary parsed from a `Cookie:` header string.
    Source: https://github.com/django/django/blob/main/django/http/cookie.py
    """
    cookiedict = {}
    for chunk in cookie.split(";"):
        if "=" in chunk:
            key, val = chunk.split("=", 1)
        else:
            # Assume an empty name per
            # https://bugzilla.mozilla.org/show_bug.cgi?id=169091
            key, val = "", chunk
        key, val = key.strip(), val.strip()
        if key or val:
            # unquote using Python's algorithm.
            cookiedict[key] = _http_cookies._unquote(val)
    return cookiedict
