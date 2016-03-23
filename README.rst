=====
djangorestframework-auth0
=====

Library to simply use Auth0 token authentication in DRF within djangorestframework-jwt

This library let you to login an specific user based on the JWT Token returned by Auth0 Javascript libraries


Detailed documentation is in the "docs" directory.

Quick start
-----------


1. Add "djangorestframework-auth0" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'djangorestframework-auth0',
    ]

2. Add `Auth0JSONWebTokenAuthentication` in your DEFAULT_AUTHENTICATION_CLASSES located at settings.py from your project::

    REST_FRAMEWORK = {
        ..,
        'DEFAULT_AUTHENTICATION_CLASSES': (
            ..,
            'djangorestframework_auth0.authentication.Auth0JSONWebTokenAuthentication',
        ),

3. Add your AUTH0_CLIENT_SECRET and AUTH0_CLIENT_ID in your settings.py file -must be the same secret and id than the frontend App-::

    AUTH0 ={
        'AUTH0_CLIENT_ID':'<YOUR_AUTH0_CLIENT_ID>',
        'AUTH0_CLIENT_SECRET':'YOUR_AUTH0_CLIENT_SECRET',
        'AUTH0_ALGORITHM':'HS256', #default used in Auth0 apps
        'JWT_AUTH_HEADER_PREFIX': 'JWT', #default prefix used by djangorestframework_jwt
    }

4. Add the `Authorization` Header to all of your REST API request, prefixing JWT to your token::

    `Authorization: JWT <YOUR_TOKEN>`

5. Use the decorator `@token_required` in all views you want to protect (not_ready_yet)

6. That's it
