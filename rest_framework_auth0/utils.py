"""DjangoRestFramework Auth0 Utils."""
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header

from rest_framework_auth0.settings import auth0_api_settings


# Handlers --------------------------------------------------------------------
def auth0_get_username_from_payload_handler(payload):
    username = payload.get(auth0_api_settings.USERNAME_FIELD)
    return username


# Authorization Utils ---------------------------------------------------------
def get_jwt_value(request):
    auth = get_authorization_header(request).split()
    auth_header_prefix = auth0_api_settings.JWT_AUTH_HEADER_PREFIX.lower()

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


# Auth0 Metadata --------------------------------------------------------------

def get_app_metadata_from_payload(payload):
    app_metadata = payload.get('app_metadata')
    return app_metadata


def get_user_metadata_from_payload(payload):
    user_metadata = payload.get('user_metadata')
    return user_metadata


# Role validation utils -------------------------------------------------------

def get_roles_from_payload(payload):
    roles = get_app_metadata_from_payload(payload)['roles']
    return roles


def validate_role(roles, role):
    return role.upper() in roles


def validate_role_from_payload(payload, role):
    roles = get_roles_from_payload(payload)
    return validate_role(roles, role)


# Group validation utils ------------------------------------------------------

def get_groups_from_payload(payload):
    groups = get_app_metadata_from_payload(payload)['authorization']['groups']
    return groups


def validate_group(group, expected_group):
    return group == expected_group


def validate_group_from_payload(payload, expected_group):
    groups = get_groups_from_payload(payload)
    return expected_group in groups
