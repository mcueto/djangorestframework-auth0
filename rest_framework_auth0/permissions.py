from __future__ import unicode_literals

from rest_framework.permissions import BasePermission
from rest_framework_auth0.authentication import Auth0JSONWebTokenAuthentication
from rest_framework_auth0.utils import validate_role_from_payload


class HasRoleBasePermission(BasePermission, Auth0JSONWebTokenAuthentication):
    """
    Allows access only to users that have an specific role in their app_metadata
    attribute, app_metadata scope required

    Example:

    {
      "app_metadata": {
        "roles": [
          "<role_name>"
        ],
        ...
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
    """

    role_name = ''

    def get_role_name(self):
        return self.role_name

    def has_permission(self, request, view):
        if request.method == 'OPTIONS':
            return True

        payload = self.get_payload(request)

        try:
            return validate_role_from_payload(payload, self.get_role_name())
        except Exception:
            return False


class HasAdminRole(HasRoleBasePermission):
    role_name = 'admin'
