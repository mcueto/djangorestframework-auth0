import base64
import jwt
import logging

from django.contrib.auth.backends import (
    RemoteUserBackend,
    get_user_model,
)
from django.contrib.auth.models import (
    Group,
)
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework_auth0.settings import (
    auth0_api_settings,
)
from rest_framework_auth0.utils import (
    get_auth_token,
    get_groups_from_payload,
)
from rest_framework.authentication import (
    BaseAuthentication,
)

get_username_from_payload = auth0_api_settings.GET_USERNAME_HANDLER

logger = logging.getLogger(__name__)


class Auth0JSONWebTokenAuthentication(BaseAuthentication, RemoteUserBackend):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj

    By default, the ``authenticate_credentials`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """

    www_authenticate_realm = 'api'
    # Create a User object if not already in the database?
    create_unknown_user = True

    def authenticate(self, request):
        """
        You should pass a header of your request: clientcode: web
        This function initialize the settings of JWT with the specific client's informations.
        """
        client = None
        payload = None

        logger.debug("authenticating user using Auth0JSONWebTokenAuthentication")

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

        auth_token = get_auth_token(request)

        if auth_token is None:
            return None

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

        # Add request param to authenticated_credentials() call
        user = self.authenticate_credentials(request, payload)

        return (user, payload)

    def authenticate_credentials(self, request, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        UserModel = get_user_model()
        remote_user = get_username_from_payload(payload)

        if not remote_user:
            msg = _('Invalid payload.')

            logger.info(
                "{message}".format(
                    message=msg
                )
            )

            raise exceptions.AuthenticationFailed(msg)
            # RemoteUserBackend behavior:
            # return

        user = None

        if auth0_api_settings.REPLACE_PIPE_FOR_DOTS_IN_USERNAME:
            username = self.clean_username(remote_user)

        else:
            username = remote_user

        logger.debug(
            "username = {username}".format(
                username=username
            )
        )

        if self.create_unknown_user:
            user, created = UserModel._default_manager.get_or_create(**{
                UserModel.USERNAME_FIELD: username
            })

            if created:
                user = self.configure_user(request, user)

        else:
            try:
                user = UserModel._default_manager.get_by_natural_key(username)

            except UserModel.DoesNotExist:
                msg = _('Invalid signature.')
                raise exceptions.AuthenticationFailed(msg)
                # RemoteUserBackend behavior:
                # pass
        user = self.configure_user_permissions(user, payload)
        return user if self.user_can_authenticate(user) else None

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(
            auth0_api_settings.AUTH_HEADER_PREFIX,
            self.www_authenticate_realm
        )

    def configure_user_permissions(self, user, payload):
        """
        Validate if AUTHORIZATION_EXTENSION is enabled, defaults to False

        If AUTHORIZATION_EXTENSION is enabled, created and associated groups
        with the current user (the user of the token).
        """
        if auth0_api_settings.AUTHORIZATION_EXTENSION:
            logger.debug(
                "Using Auth0 Authorization Extension"
            )

            logger.debug(
                "Clearing groups for user: {username}".format(
                    username=user.username
                )
            )

            user.groups.clear()

            try:
                logger.debug(
                    "Getting groups from payload"
                )

                groups = get_groups_from_payload(payload)

                logger.debug(
                    "Groups: {groups}".format(
                        groups=groups
                    )
                )

            except Exception:  # No groups where defined in Auth0?
                logger.warning(
                    "No groups were defined for user: {username}".format(
                        username=user.username
                    )
                )

                return user

            for user_group in groups:
                group, created = Group.objects.get_or_create(name=user_group)

                logger.debug(
                    "Associating group {group} with user {username}".format(
                        group=group,
                        username=user.username
                    )
                )

                user.groups.add(group)

        return user

    def clean_username(self, username):
        """
        Cleans the "username" prior to using it to get or create the user object.
        Returns the cleaned username.

        Auth0 default username (user_id) field returns, e.g. auth0|123456789...xyz
        which contains illegal characters ('|').
        """
        logger.debug("Cleaning username")

        username = username.replace('|', '.')

        logger.debug(
            "Clean username: {username}".format(
                username=username
            )
        )

        return username
