import jwt

from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import api_settings as jwt_api_settings
from djangorestframework_auth0.settings import api_settings

from rest_framework_jwt.authentication import BaseJSONWebTokenAuthentication

jwt_decode_handler = jwt_api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = jwt_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER

class Auth0JSONWebTokenAuthentication(BaseJSONWebTokenAuthentication):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    # def authenticate(self, request):
    #     """
    #     Returns a two-tuple of `User` and token if a valid signature has been
    #     supplied using JWT-based authentication.  Otherwise returns `None`.
    #     """
    #     jwt_value = self.get_jwt_value(request)
    #
    #     # print("jwt_value")
    #     # print(jwt_value)
    #
    #     if jwt_value is None:
    #         return None
    #
    #     # print("pretry")
    #     try:
    #         # print("decode_handler")
    #         # print(jwt_decode_handler)
    #
    #         payload = jwt_decode_handler(jwt_value)
    #         # print("payload")
    #         # print(payload)
    #     except jwt.ExpiredSignature:
    #         msg = _('Signature has expired.')
    #         raise exceptions.AuthenticationFailed(msg)
    #     except jwt.DecodeError:
    #         msg = _('Error decoding signature.')
    #         raise exceptions.AuthenticationFailed(msg)
    #     except jwt.InvalidTokenError:
    #         raise exceptions.AuthenticationFailed()
    #
    #     user = self.authenticate_credentials(payload)
    #     # print(user)
    #     # print("user")
    #
    #     return (user, jwt_value)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        User = get_user_model()

        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            user, created = User.objects.get_or_create(username=username)

            if created:
                user.save()

        except User.DoesNotExist:
            msg = _('Invalid signature.')
            raise exceptions.AuthenticationFailed(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)

        return user

    def get_jwt_value(self, request):
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

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(jwt_api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm)
