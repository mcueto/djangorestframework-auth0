"""DjangoRestFramework Auth0 Utils."""
import jwt
import logging
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header
from rest_framework_auth0.settings import auth0_api_settings

logger = logging.getLogger(__name__)


# Handlers --------------------------------------------------------------------
def auth0_get_username_from_payload_handler(payload):
    username = payload.get(auth0_api_settings.USERNAME_FIELD)

    return username


# Authorization Utils ---------------------------------------------------------
def get_auth_token(request):
    auth = get_authorization_header(request).split()
    auth_header_prefix = auth0_api_settings.JWT_AUTH_HEADER_PREFIX.lower()

    if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
        return None

    if len(auth) == 1:
        msg = _('Invalid Authorization header. No credentials provided.')

        logger.info(
            "{message}".format(
                message=msg
            )
        )

        raise exceptions.AuthenticationFailed(msg)

    elif len(auth) > 2:
        msg = _('Invalid Authorization header. Credentials string '
                'should not contain spaces.')

        logger.info(
            "{message}".format(
                message=msg
            )
        )

        raise exceptions.AuthenticationFailed(msg)

    return auth[1]


# Auth0 Metadata --------------------------------------------------------------

def get_app_metadata_from_payload(payload):
    logger.info(
        "Getting app_metadata from payload"
    )

    app_metadata = payload.get('app_metadata')

    logger.debug(
        "app_metadata: {app_metadata}".format(
            app_metadata=app_metadata
        )
    )

    return app_metadata


def get_user_metadata_from_payload(payload):
    logger.info(
        "Getting user_metadata from payload"
    )

    user_metadata = payload.get('user_metadata')

    logger.debug(
        "user_metadata: {user_metadata}".format(
            user_metadata=user_metadata
        )
    )

    return user_metadata


# Role validation utils -------------------------------------------------------

def get_roles_from_payload(payload):
    logger.info(
        "Getting roles from payload"
    )

    roles = get_app_metadata_from_payload(payload)['authorization']['roles']

    logger.debug(
        "roles: {roles}".format(
            roles=roles
        )
    )

    return roles


def validate_role(roles, role):
    logger.info(
        "Validating role"
    )

    is_role_valid = role in roles

    logger.info(
        "Is the role valid: {is_role_valid}".format(
            is_role_valid=is_role_valid
        )
    )

    return is_role_valid


def validate_role_from_payload(payload, role):
    logger.info(
        "Validating role from payload"
    )

    roles = get_roles_from_payload(payload)

    logger.debug(
        "Validating role {role} on {roles}".format(
            role=role,
            roles=roles
        )
    )

    return validate_role(roles, role)


# Group validation utils ------------------------------------------------------

def get_groups_from_payload(payload):
    logger.info(
        "Getting groups from payload"
    )

    groups = get_app_metadata_from_payload(payload)['authorization']['groups']

    logger.debug(
        "Groups: {groups}".format(
            groups=groups
        )
    )

    return groups


def jwt_get_secret_key(payload=None):
    """
    For enhanced security you may want to use a secret key based on user.
    This way you have an option to logout only this user if:
        - token is compromised
        - password is changed
        - etc.
    """
    if auth0_api_settings.JWT_GET_USER_SECRET_KEY:
        User = get_user_model()  # noqa: N806
        user = User.objects.get(pk=payload.get('user_id'))
        key = str(auth0_api_settings.JWT_GET_USER_SECRET_KEY(user))

        return key

    return auth0_api_settings.JWT_SECRET_KEY


def validate_group(group, expected_group):
    return group == expected_group


def validate_group_from_payload(payload, expected_group):
    groups = get_groups_from_payload(payload)
    return expected_group in groups
