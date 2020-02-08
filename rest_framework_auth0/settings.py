from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'AUTH0', None)

DEFAULTS = {
    'AUTH_HEADER_PREFIX': 'Bearer',
    'AUTH_COOKIE_NAME': None,  # if you want to use cookie instead of header, set this setting
    'AUTHORIZATION_EXTENSION': False,
    'USERNAME_FIELD': 'sub',
    'CLIENT_CODE_HEADER': 'Client_Code',
    'CLIENTS': {},
    'REPLACE_PIPE_FOR_DOTS_IN_USERNAME': True,
    # Handlers
    'GET_USERNAME_HANDLER':
    'rest_framework_auth0.utils.get_username_from_payload',
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'GET_USERNAME_HANDLER',
)

auth0_api_settings = APISettings(
    USER_SETTINGS,
    DEFAULTS,
    IMPORT_STRINGS
)
