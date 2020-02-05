from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'AUTH0', None)

DEFAULTS = {
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'AUTHORIZATION_EXTENSION': False,
    'USERNAME_FIELD': 'sub',
    'CLIENT_CODE': 'Client_Code',
    'CLIENTS': {},
    'REPLACE_PIPE_FOR_DOTS_IN_USERNAME': True,
    'COOKIE_NAME': None,
    # Handlers
    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
    'rest_framework_auth0.utils.auth0_get_username_from_payload_handler',
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'JWT_PAYLOAD_GET_USERNAME_HANDLER',
)

auth0_api_settings = APISettings(
    USER_SETTINGS,
    DEFAULTS,
    IMPORT_STRINGS
)
