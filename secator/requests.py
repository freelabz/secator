import requests as requests_lib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_session(allowed_methods=None):
    # allowed_methods: which HTTP methods may be retried. None -> urllib3 default
    # (GET/HEAD/PUT/DELETE/OPTIONS/TRACE, i.e. NOT POST). Pass a set including 'POST'
    # for callers whose writes are safe to retry (e.g. idempotency-keyed requests).
    retry_kwargs = dict(
        total=3,
        backoff_factor=1,
        status_forcelist=[408, 429, 500, 502, 503, 504],
    )
    if allowed_methods is not None:
        retry_kwargs['allowed_methods'] = allowed_methods
    retries = Retry(**retry_kwargs)
    session = requests_lib.Session()
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session


requests = get_session()
requests.RequestException = requests_lib.RequestException
requests.codes = requests_lib.codes
