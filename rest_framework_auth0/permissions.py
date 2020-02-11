from __future__ import unicode_literals
import logging

from rest_framework.permissions import BasePermission

from rest_framework_auth0.utils import (
    get_auth_token,
    get_client_setting,
    get_groups_from_payload,
    decode_auth_token,
    validate_role_from_payload,
    validate_group_from_payload,
    validate_permission_from_payload,
)

logger = logging.getLogger(__name__)


class HasRoleBasePermission(BasePermission):
    """
    Allows access only to users that have an specific role.

    Allows access only to users that have an specific role in their
    app_metadata attribute, which is obtained using Auth0 management API +
    Auth0 authorization extension.

    Example for a ToDos app:

    {
      "app_metadata": {
        "authorization": {
            'groups': [
                'users',
                'admin'
            ],
            'roles': [
                'ToDos admin']
            ,
            'permissions': [
                'read:todos',
                'edit:todos',
                'create:todos'
            ]
        }
      },
      "user_metadata": {
        ...
      },
      "iss": "https://your_user.auth0.com/",
      "sub": "auth0|123456789876543212345678",
      "aud": "client_id",
      "exp": 1476851700,
      "iat": 1476815700
    }

    NOTE: This payload can be obtained only through Auth0 management API so
    it not contain the same info as the user token.

    In the old flow you could obtain this using "app_metadata" scope but now
    this metadata is only available through the current flow(OIDC compliant).
    """

    role_name = ""

    def get_role_name(self):
        return self.role_name

    def has_permission(self, request, view):

        if request.method == 'OPTIONS':
            return True

        client = get_client_setting(request)
        auth_token = get_auth_token(request)

        try:
            payload = decode_auth_token(
                client=client,
                auth_token=auth_token
            )

            return validate_role_from_payload(payload, self.get_role_name())

        except Exception as e:
            return False


class HasAdminRole(HasRoleBasePermission):
    role_name = 'admin'


# Group based permissions -----------------------------------------------------

class HasGroupBasePermission(BasePermission):
    group_name = ""

    def get_group_name(self):
        return self.group_name

    def has_permission(self, request, view):

        if request.method == 'OPTIONS':
            return True

        client = get_client_setting(request)
        auth_token = get_auth_token(request)

        try:
            payload = decode_auth_token(
                client=client,
                auth_token=auth_token
            )

            return validate_group_from_payload(payload, self.get_group_name())

        except Exception as e:
            return False


# Permission based permissions ------------------------------------------------

class HasPermissionBasePermission(BasePermission):
    permission_name = ""

    def get_permission_name(self):
        return self.permission_name

    def has_permission(self, request, view):

        if request.method == 'OPTIONS':
            return True

        client = get_client_setting(request)
        auth_token = get_auth_token(request)

        try:
            payload = decode_auth_token(
                client=client,
                auth_token=auth_token
            )

            return validate_permission_from_payload(payload, self.get_permission_name())

        except Exception as e:
            return False
