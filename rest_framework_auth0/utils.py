"""DjangoRestFramework Auth0 Utils."""
import base64
import logging
import jwt
from django.utils.encoding import force_str
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header
from rest_framework_auth0.settings import auth0_api_settings
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0

logger = logging.getLogger(__name__)


def validate_authorization_header(auth_header):
    """
    Validate if the authorization header has the correct format.

    The authorization header is validated in order to ensure that has:
    - The correct prefix that match the one in settings(`Bearer` by default)
    - The num of items on auth_header must be 2(prefix and token)

    """
    logger.debug(
        "Validating authorization header"
    )

    is_valid = False

    try:
        auth_header_prefix = force_str(auth_header[0])
        # auth_token = force_str(auth_header[1])
        expected_auth_header_prefix = auth0_api_settings.AUTH_HEADER_PREFIX

        # If header prefix is diferent than expected, the user won't log in
        if auth_header_prefix.lower() != expected_auth_header_prefix.lower():
            logger.warning(
                "Invalid header prefix, expected {expected} found {found}".format(
                    expected=expected_auth_header_prefix.lower(),
                    found=auth_header_prefix.lower()
                )
            )

            msg = _('Invalid Authorization header.')

            raise exceptions.AuthenticationFailed(msg)

        # If token is not present, the user won't log in
        if len(auth_header) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')

            logger.info(
                "{message}".format(
                    message=msg
                )
            )

            raise exceptions.AuthenticationFailed(msg)

        # If token is "trimmed", the user won't log in
        elif len(auth_header) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')

            logger.info(
                "{message}".format(
                    message=msg
                )
            )

            raise exceptions.AuthenticationFailed(msg)

        is_valid = True

    except Exception as e:
        pass

    return is_valid


# Handlers --------------------------------------------------------------------
def get_username_from_payload(payload):
    username = payload.get(auth0_api_settings.USERNAME_FIELD)

    return username


# Authorization Utils ---------------------------------------------------------
def get_auth_token(request):
    """
    Return the current request auth token.

    The token is get using HTTP_AUTHORIZATION header on each request, or
    using a cookie if AUTH_COOKIE_NAME setting is set.

    The header is validated in order to ensure request is formatted as needed.

    A valid authorization header look like(default settings):
    ```
    Authorization: Bearer <auth0_generated_token>
    ```
    """
    logger.debug(
        "Getting auth token"
    )

    auth_header = get_authorization_header(request).split()
    auth_token = None

    if validate_authorization_header(auth_header):
        logger.debug(
            "Authorization header is valid"
        )
        auth_token = force_str(auth_header[1])

    # If authorization header doesn't exists, use a cookie
    elif not auth_header and auth0_api_settings.AUTH_COOKIE_NAME:
        logger.warning(
            "Using Cookie instead of header"
        )
        auth_token = request.COOKIES.get(auth0_api_settings.AUTH_COOKIE_NAME)

    else:
        logger.debug(
            "Invalid authorization header"
        )
        auth_token = None  # Just for maker it clear

    return auth_token


def decode_auth_token(client, auth_token):
    payload = None

    try:

        # RS256 Related configurations
        if(client['AUTH0_ALGORITHM'].upper() == "RS256"):
            logger.debug(
                "Using RS256 algorithm"
            )

            payload = jwt.decode(
                auth_token,
                client['PUBLIC_KEY'],
                audience=client['AUTH0_AUDIENCE'],
                algorithm=client['AUTH0_ALGORITHM'],
            )

        elif(client['AUTH0_ALGORITHM'].upper() == "HS256"):
            client_secret = None

            logger.debug(
                "Using HS256 algorithm"
            )

            if client['CLIENT_SECRET_BASE64_ENCODED']:
                logger.debug(
                    "Client secret is base64 encoded"
                )

                client_secret = base64.b64decode(
                    client['AUTH0_CLIENT_SECRET'].replace("_", "/").replace("-", "+")
                )

            else:
                logger.debug(
                    "Client secret is not base64 encoded"
                )

                client_secret = client['AUTH0_CLIENT_SECRET']

            logger.debug(
                "client_secret = {client_secret}".format(
                    client_secret=client_secret
                )
            )

            payload = jwt.decode(
                auth_token,
                client_secret,
                audience=client['AUTH0_AUDIENCE'],
                algorithm=client['AUTH0_ALGORITHM'],
            )

        else:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)

        logger.debug(
            "payload = {payload}".format(
                payload=payload
            )
        )

    except jwt.ExpiredSignature:
        msg = _('Signature has expired.')

        logger.info(
            "{message}".format(
                message=msg
            )
        )

        raise exceptions.AuthenticationFailed(msg)

    except jwt.DecodeError:
        msg = _('Error decoding signature.')

        logger.info(
            "{message}".format(
                message=msg
            )
        )

        raise exceptions.AuthenticationFailed(msg)

    except jwt.InvalidTokenError:
        msg = _('Invalid token.')

        logger.info(
            "{message}".format(
                message=msg
            )
        )

        raise exceptions.AuthenticationFailed()

    return payload


def get_client_setting(request):
    client = None

    client_code = request.META.get(
        "HTTP_" + auth0_api_settings.CLIENT_CODE_HEADER.upper()
    ) or 'default'

    logger.debug(
        "client_code = {client_code}".format(
            client_code=client_code
        )
    )

    if client_code in auth0_api_settings.CLIENTS:
        client = auth0_api_settings.CLIENTS[client_code]

        logger.debug(
            "client = {client}".format(
                client=client
            )
        )

    else:
        msg = _('Invalid Client Code.')

        logger.warning(
            "{msg}: {client_code}".format(
                msg=msg,
                client_code=client_code
            )
        )

        raise exceptions.AuthenticationFailed(msg)

    return client


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

def get_management_api_token():
    domain = auth0_api_settings.MANAGEMENT_API['AUTH0_DOMAIN']
    client_id = auth0_api_settings.MANAGEMENT_API['AUTH0_CLIENT_ID']
    client_secret = auth0_api_settings.MANAGEMENT_API['AUTH0_CLIENT_SECRET']

    get_token = GetToken(domain)
    token = get_token.client_credentials(
        client_id,
        client_secret,
        'https://{domain}/api/v2/'.format(
            domain=domain
        )
    )

    return token['access_token']


def get_user_from_management_api(user_id):
    domain = auth0_api_settings.MANAGEMENT_API['AUTH0_DOMAIN']
    management_api_token = get_management_api_token()

    auth0 = Auth0(domain, management_api_token)

    return auth0.users.get(user_id)


def get_app_metadata_from_user(user):
    return user.get('app_metadata')


def get_authorization_metadata_from_user(user):
    app_metadata = get_app_metadata_from_user(user)
    return app_metadata.get('authorization')


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


def validate_group(group, expected_group):
    return group == expected_group


def validate_group_from_payload(payload, expected_group):
    groups = get_groups_from_payload(payload)
    return expected_group in groups
