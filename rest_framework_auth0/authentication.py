import base64
import jwt

from django.contrib.auth.backends import RemoteUserBackend, get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import ugettext as _
from rest_framework import exceptions

from rest_framework_auth0.settings import (
    jwt_api_settings,
    auth0_api_settings,
)
from rest_framework_auth0.utils import get_groups_from_payload

from django.utils.encoding import smart_text
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)
from rest_framework_jwt.settings import api_settings

jwt_decode_handler = auth0_api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = auth0_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class Auth0JSONWebTokenAuthentication(BaseAuthentication, RemoteUserBackend):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

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
        client_code = request.META.get("HTTP_" + auth0_api_settings.CLIENT_CODE.upper()) or 'default'

        if client_code in auth0_api_settings.CLIENTS:
            client = auth0_api_settings.CLIENTS[client_code]
        else:
            msg = _('Invalid Client Code.')
            raise exceptions.AuthenticationFailed(msg)

        jwt_api_settings.JWT_ALGORITHM = client['AUTH0_ALGORITHM']
        jwt_api_settings.JWT_AUDIENCE = client['AUTH0_CLIENT_ID']
        jwt_api_settings.JWT_AUTH_HEADER_PREFIX = auth0_api_settings.JWT_AUTH_HEADER_PREFIX

        # RS256 Related configurations
        if(client['AUTH0_ALGORITHM'].upper() == "HS256"):
            if client['CLIENT_SECRET_BASE64_ENCODED']:
                jwt_api_settings.JWT_SECRET_KEY = base64.b64decode(
                    client['AUTH0_CLIENT_SECRET'].replace("_", "/").replace("-", "+")
                )
            else:
                jwt_api_settings.JWT_SECRET_KEY = client['AUTH0_CLIENT_SECRET']

        if(client['AUTH0_ALGORITHM'].upper() == "RS256"):
            jwt_api_settings.JWT_PUBLIC_KEY = client['PUBLIC_KEY']

        # Code copied from rest_framework_jwt/authentication.py#L28
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = jwt_decode_handler(jwt_value)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        # Add request param to authenticated_credentials() call
        user = self.authenticate_credentials(request, payload)

        return (user, payload)

    def authenticate_credentials(self, request, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        UserModel = get_user_model()
        remote_user = jwt_get_username_from_payload(payload)

        if not remote_user:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)
            # RemoteUserBackend behavior:
            # return

        user = None

        if auth0_api_settings.REPLACE_PIPE_FOR_DOTS_IN_USERNAME:
            username = self.clean_username(remote_user)
        else:
            username = remote_user

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
        return '{0} realm="{1}"'.format(api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm)

    def configure_user_permissions(self, user, payload):
        """
        Validate if AUTHORIZATION_EXTENSION is enabled, defaults to False

        If AUTHORIZATION_EXTENSION is enabled, created and associated groups
        with the current user (the user of the token).
        """
        if auth0_api_settings.AUTHORIZATION_EXTENSION:
            user.groups.clear()
            try:
                groups = get_groups_from_payload(payload)
            except Exception:  # No groups where defined in Auth0?
                return user
            for user_group in groups:
                group, created = Group.objects.get_or_create(name=user_group)
                user.groups.add(group)

        return user

    def clean_username(self, username):
        """
        Cleans the "username" prior to using it to get or create the user object.
        Returns the cleaned username.

        Auth0 default username (user_id) field returns, e.g. auth0|123456789...xyz
        which contains illegal characters ('|').
        """
        username = username.replace('|', '.')
        return username

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if api_settings.JWT_AUTH_COOKIE:
                return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
            return None

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]
