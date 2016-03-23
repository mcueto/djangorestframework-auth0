import datetime
import base64

from django.conf import settings
from rest_framework.settings import APISettings
from rest_framework_jwt.settings import api_settings as jwt_settings
from rest_framework_auth0.utils import auth0_get_username_from_payload_handler


USER_SETTINGS = getattr(settings, 'AUTH0', None)

DEFAULTS = {
    'AUTH0_CLIENT_ID':'',
    'AUTH0_CLIENT_SECRET':'',
    'AUTH0_ALGORITHM':'HS256',
    'JWT_AUTH_HEADER_PREFIX':'JWT'
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS)


jwt_settings.JWT_ALGORITHM = api_settings.AUTH0_ALGORITHM
jwt_settings.JWT_SECRET_KEY = base64.b64decode(api_settings.AUTH0_CLIENT_SECRET.replace("_","/").replace("-","+"))
jwt_settings.JWT_AUDIENCE = api_settings.AUTH0_CLIENT_ID
jwt_settings.JWT_AUTH_HEADER_PREFIX = api_settings.JWT_AUTH_HEADER_PREFIX
jwt_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER = auth0_get_username_from_payload_handler
