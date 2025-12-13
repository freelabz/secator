import requests as requests_lib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_session():
    session = requests_lib.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[408, 429, 500, 502, 503, 504]
    )
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session


requests = get_session()
requests.RequestException = requests_lib.RequestException
requests.codes = requests_lib.codes
