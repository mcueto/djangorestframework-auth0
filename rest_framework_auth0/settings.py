import base64

from django.conf import settings
from rest_framework.settings import APISettings
from rest_framework_jwt.settings import api_settings as jwt_api_settings

USER_SETTINGS = getattr(settings, 'AUTH0', None)

DEFAULTS = {
    'AUTH0_CLIENT_ID': '',
    'AUTH0_CLIENT_SECRET': '',
    'AUTH0_ALGORITHM': 'HS256',
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'AUTHORIZATION_EXTENSION': False,
    'CLIENT_SECRET_BASE64_ENCODED': True,
    'USERNAME_FIELD': 'sub',
    # Handlers
    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
    'rest_framework_auth0.utils.auth0_get_username_from_payload_handler',
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'JWT_PAYLOAD_GET_USERNAME_HANDLER',
)

auth0_api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)

# Replace rest_framework_jwt api settings
if auth0_api_settings.CLIENT_SECRET_BASE64_ENCODED:
    jwt_api_settings.JWT_SECRET_KEY = base64.b64decode(
        auth0_api_settings.AUTH0_CLIENT_SECRET.replace("_", "/").replace("-", "+")
    )
else:
    jwt_api_settings.JWT_SECRET_KEY = auth0_api_settings.AUTH0_CLIENT_SECRET

jwt_api_settings.JWT_ALGORITHM = auth0_api_settings.AUTH0_ALGORITHM
jwt_api_settings.JWT_AUDIENCE = auth0_api_settings.AUTH0_CLIENT_ID
jwt_api_settings.JWT_AUTH_HEADER_PREFIX = auth0_api_settings.JWT_AUTH_HEADER_PREFIX
jwt_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER = auth0_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER
