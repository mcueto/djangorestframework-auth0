from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)
import jwt
from rest_framework import exceptions
from django.utils.encoding import smart_text
from rest_framework_jwt.settings import api_settings as jwt_api_settings

#copy if neccesary(review if import or just copy)
def jwt_decode_handler(token):
    options = {
        'verify_exp': jwt_api_settings.JWT_VERIFY_EXPIRATION,
    }

    return jwt.decode(
        token,
        jwt_api_settings.JWT_SECRET_KEY,
        # jwt_api_settings.JWT_PUBLIC_KEY or jwt_api_settings.JWT_SECRET_KEY,
        jwt_api_settings.JWT_VERIFY,
        options=options,
        leeway=jwt_api_settings.JWT_LEEWAY,
        audience=jwt_api_settings.JWT_AUDIENCE,
        issuer=jwt_api_settings.JWT_ISSUER,
        algorithms=[jwt_api_settings.JWT_ALGORITHM]
    )


def auth0_get_username_from_payload_handler(payload):
    # print("get auth0 user")
    return payload.get('sub')

def get_jwt_value(request):
    auth = get_authorization_header(request).split()
    auth_header_prefix = jwt_api_settings.JWT_AUTH_HEADER_PREFIX.lower()

    if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
        return None

    if len(auth) == 1:
        msg = _('Invalid Authorization header. No credentials provided.')
        raise exceptions.AuthenticationFailed(msg)
    elif len(auth) > 2:
        msg = _('Invalid Authorization header. Credentials string '
                'should not contain spaces.')
        raise exceptions.AuthenticationFailed(msg)

    return auth[1]

def get_app_metadata_from_payload(payload):
    app_metadata = payload.get('app_metadata')

    return app_metadata

def get_user_metadata_from_payload(payload):
    user_metadata = payload.get('user_metadata')

    return user_metadata


#ROLES

def get_role_from_payload(payload):

    roles = get_app_metadata_from_payload(payload)["roles"]

    return roles


def validate_role(roles, role):
    if(role.upper in roles):
        return True
    else:
        return False

def validate_role_from_payload(payload, role):
    roles = get_role_from_payload(payload)
    return validate_role(roles, role)

#GROUPS

def get_group_from_payload(payload):
    group = get_app_metadata_from_payload(payload)["groups"]

    return group


def validate_group(group, expected_group):
    if(group == expected_group):
        return True
    else:
        return False

def validate_group_from_payload(payload, expected_group):
    group = get_group_from_payload(payload)
    return validate_group(group, expected_group)
