"""Private bounded worker for the continuous runner's authenticated health check.

Only the parent calls this module, with credentials over stdin. It terminates
and reaps this process at the total deadline, stop request or ownership loss.
"""
import json
import sys
import urllib.request


def main():
    try:
        value = json.loads(sys.stdin.buffer.read(131073))
        request = urllib.request.Request(value['base_url'].rstrip('/') + '/models',
            headers={'Authorization': 'Bearer ' + value['key']})

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(1048577)
        if len(raw) > 1048576:
            return 1
        data = json.loads(raw)
        return 0 if any(row.get('id') == value['model'] for row in data.get('data', [])) else 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
