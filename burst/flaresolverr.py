# -*- coding: utf-8 -*-
"""
FlareSolverr Cloudflare bypass client.
"""
from future.utils import PY3
import requests
from elementum.provider import log, get_setting
from .client import change_agent

if PY3:
    from urllib.parse import urlencode
    unicode = str
else:
    from urllib import urlencode
    unicode = unicode

flaresolverr_enabled = get_setting("flaresolverr_enabled", bool)
flaresolverr_url = get_setting("flaresolverr_url", unicode)
if not flaresolverr_url:
    flaresolverr_url = "http://localhost:8191"
flaresolverr_url = flaresolverr_url.strip().rstrip("/")

DEFAULT_ENDPOINT = "http://localhost:8191"
DEFAULT_MAX_TIMEOUT = 60000

CHALLENGE_INDICATORS = [
    "just a moment",
    "cf-challenge",
    "challenge-platform",
    "__cf_chl",
]
CHALLENGE_STATUSES = (403, 503)


def is_challenge(status, content):
    if status not in CHALLENGE_STATUSES:
        return False
    if not content:
        return False

    lowered = content.lower()
    for indicator in CHALLENGE_INDICATORS:
        if indicator in lowered:
            return True
    return False


def solve(endpoint, url, method="GET", post_data=None, headers=None, max_timeout=DEFAULT_MAX_TIMEOUT, client=None):
    try:
        api_url = "%s/v1" % (endpoint or flaresolverr_url or DEFAULT_ENDPOINT)
        command = "request.post" if method and method.upper() == "POST" else "request.get"

        payload = {
            "cmd": command,
            "url": url,
            "maxTimeout": max_timeout,
        }

        # Пробрасываем куки авторизации (Cookie Sync / Session) во FlareSolverr
        if client and hasattr(client, '_cookies') and client._cookies:
            req_cookies = []
            for cookie in client._cookies:
                req_cookies.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path
                })
            if req_cookies:
                payload["cookies"] = req_cookies

        if command == "request.post" and post_data:
            if isinstance(post_data, dict):
                payload["postData"] = urlencode(post_data)
            else:
                payload["postData"] = post_data
        if headers:
            payload["headers"] = headers

        log.debug("FlareSolverr %s request for %s to %s" % (command, repr(url), repr(api_url)))
        response = requests.post(api_url, json=payload, timeout=(max_timeout / 1000.0) + 10)
        data = response.json()

        if data.get("status") != "ok":
            log.error("FlareSolverr could not solve %s: %s" % (repr(url), data.get("message", repr(data))))
            return None

        solution = data.get("solution")
        if not solution:
            log.error("FlareSolverr returned no solution for %s" % repr(url))
            return None

        log.debug("FlareSolverr solved %s with status %s" % (repr(url), solution.get("status")))
        return solution
    except Exception as e:
        import traceback
        log.error("FlareSolverr solve error for %s: %s" % (repr(url), repr(e)))
        map(log.debug, traceback.format_exc().split("\n"))
        return None


def _merge_cookie(client, cookie):
    name = cookie.get("name")
    domain = cookie.get("domain")
    value = cookie.get("value")
    if not name or value is None:
        return False

    host = (domain or "").lstrip(".")
    for existing in list(client._cookies):
        if existing.name == name and existing.domain.lstrip(".") == host:
            try:
                client._cookies.clear(existing.domain, existing.path, existing.name)
            except Exception:
                pass

    expiry = cookie.get("expires") or 0
    expiration_date = None
    try:
        if int(expiry) > 0:
            expiration_date = int(expiry)
    except Exception:
        expiration_date = None

    client.add_cookie({
        "domain": domain or "",
        "name": name,
        "value": value,
        "path": cookie.get("path") or "/",
        "secure": bool(cookie.get("secure")),
        "expirationDate": expiration_date,
        "rest": {"HttpOnly": bool(cookie.get("httpOnly"))},
    })
    return True


def apply_solution(client, solution):
    try:
        if not solution:
            return False

        user_agent = solution.get("userAgent")
        if user_agent:
            client.user_agent = user_agent
            change_agent(user_agent)

        cookies = solution.get("cookies")
        if cookies:
            client._read_cookies()
            added = 0
            for cookie in cookies:
                if _merge_cookie(client, cookie):
                    added += 1
            if added:
                log.debug("FlareSolverr merged %d cookies into the client" % added)
                client.save_cookies()

        client.content = solution.get("response", "")
        log.debug("FlareSolverr Response Preview: %s" % repr(client.content[:500]))
        client.status = solution.get("status", 200)

        return True
    except Exception as e:
        import traceback
        log.error("FlareSolverr failed applying solution: %s" % repr(e))
        map(log.debug, traceback.format_exc().split("\n"))
        return False


def pre_solve(client, url):
    if not flaresolverr_enabled or not flaresolverr_url:
        return False
    if not url:
        return False

    log.debug("FlareSolverr pre-solving %s" % repr(url))
    solution = solve(flaresolverr_url, url, method="GET", client=client)
    return apply_solution(client, solution)
