import json
import certifi
import ssl

from urllib.request import HTTPSHandler
from django.conf import settings

from captcha._compat import (
    build_opener, ProxyHandler, PY2, Request, urlencode
)
from captcha.constants import DEFAULT_RECAPTCHA_DOMAIN


RECAPTCHA_SUPPORTED_LANUAGES = ("en", "nl", "fr", "de", "pt", "ru", "es", "tr")


class RecaptchaResponse(object):
    def __init__(self, is_valid, error_codes=None, extra_data=None):
        self.is_valid = is_valid
        self.error_codes = error_codes or []
        self.extra_data = extra_data or {}


def recaptcha_request(params):
    request_object = Request(
        url="https://%s/recaptcha/api/siteverify" % getattr(
            settings, "RECAPTCHA_DOMAIN", DEFAULT_RECAPTCHA_DOMAIN
        ),
        data=params,
        headers={
            "Content-type": "application/x-www-form-urlencoded",
            "User-agent": "reCAPTCHA Django"
        }
    )

    # Add proxy values to opener if needed.
    opener_args = []
    proxies = getattr(settings, "RECAPTCHA_PROXY", {})
    if proxies:
        opener_args.append(ProxyHandler(proxies))

    # Create the certifi-based HTTPS handler
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    https_handler = HTTPSHandler(context=ssl_context)

    opener_args.append(https_handler)

    opener = build_opener(*opener_args)

    # Get response from POST to Google endpoint.
    return opener.open(
        request_object,
        timeout=getattr(settings, "RECAPTCHA_VERIFY_REQUEST_TIMEOUT", 10)
    )


def submit(recaptcha_response, private_key, remoteip):
    """
    Submits a reCAPTCHA request for verification. Returns RecaptchaResponse
    for the request

    recaptcha_response -- The value of reCAPTCHA response from the form
    private_key -- your reCAPTCHA private key
    remoteip -- the user's ip address
    """
    params = urlencode({
        "secret": private_key,
        "response": recaptcha_response,
        "remoteip": remoteip,
    })

    if not PY2:
        params = params.encode("utf-8")

    response = recaptcha_request(params)
    data = json.loads(response.read().decode("utf-8"))
    response.close()
    return RecaptchaResponse(
        is_valid=data.pop("success"),
        error_codes=data.pop("error-codes", None),
        extra_data=data
    )
