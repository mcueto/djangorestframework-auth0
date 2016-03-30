=====
djangorestframework-auth0
=====

Warning::
-------

    **This library is in an early stage of development**, when i finish the first "stable" version, i will add it to pip and register the first release to github


Library to simply use Auth0 token authentication in DRF within djangorestframework-jwt

This library let you to login an specific user based on the JWT Token returned by Auth0 Javascript libraries


Detailed documentation is in the "docs" directory.

Installation
-----------

1. Using `pip` install the library cloning the repository with following command::

    pip install -e git+https://github.com/mcueto/djangorestframework-auth0.git#egg=rest_framework_auth0

Quick start
-----------

1. Add "django.contrib.auth to INSTALLED_APPS settings like this::

    INSTALLED_APPS = [
        ...
        'django.contrib.auth',
        ...
    ]

This will allow us to login as an specific user as well as auto-creating users when they don't exist

1. Add "djangorestframework-auth0" to your INSTALLED_APPS **after** `rest_framework_jwt` setting like this::

    INSTALLED_APPS = [
        ...,
        'rest_framework_jwt',
        'djangorestframework-auth0',
    ]

2. Add `Auth0JSONWebTokenAuthentication` in your DEFAULT_AUTHENTICATION_CLASSES located at settings.py from your project::

    REST_FRAMEWORK = {
        ...,
        'DEFAULT_AUTHENTICATION_CLASSES': (
            ...,
            'rest_framework_auth0.authentication.Auth0JSONWebTokenAuthentication',
        ),
    }

3. Add your AUTH0_CLIENT_SECRET and AUTH0_CLIENT_ID in your settings.py file -must be the same secret and id than the frontend App-::

    AUTH0 = {
        'AUTH0_CLIENT_ID':'<YOUR_AUTH0_CLIENT_ID>',
        'AUTH0_CLIENT_SECRET':'<YOUR_AUTH0_CLIENT_SECRET>',
        'AUTH0_ALGORITHM':'HS256', #default used in Auth0 apps
        'JWT_AUTH_HEADER_PREFIX': 'JWT', #default prefix used by djangorestframework_jwt
    }

4. Add the `Authorization` Header to all of your REST API request, prefixing JWT to your token::

    Authorization: JWT <AUTH0_GIVEN_TOKEN>

5. Use the decorator `@token_required` in all views you want to protect (not_ready_yet)

6. That's it
