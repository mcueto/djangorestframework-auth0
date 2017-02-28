from django.contrib.auth.models import Group
from django.contrib.auth.backends import RemoteUserBackend, get_user_model
from django.utils.translation import ugettext as _

from rest_framework import exceptions
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

from rest_framework_auth0.settings import auth0_api_settings, jwt_api_settings
from rest_framework_auth0.utils import get_groups_from_payload


jwt_decode_handler = jwt_api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = jwt_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class Auth0JSONWebTokenAuthentication(JSONWebTokenAuthentication, RemoteUserBackend):
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

    # Create a User object if not already in the database?
    create_unknown_user = True


    def get_payload(self, request):
        """
        Returns the request's payload
        """
        user, jwt_value = self.authenticate(request)
        if jwt_value is None:
            return False
        # jwt_decode_handler errors are managed on parent's authenticate method
        payload = jwt_decode_handler(jwt_value)
        return payload


    def authenticate_credentials(self, payload):
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
        username = self.clean_username(remote_user)

        if self.create_unknown_user:
            user, created = UserModel._default_manager.get_or_create(**{
                UserModel.USERNAME_FIELD: username
            })
            if created:
                user = self.configure_user(user)
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
