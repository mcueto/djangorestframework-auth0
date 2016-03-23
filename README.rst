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

2. Add your AUTH0_CLIENT_SECRET and AUTH0_CLIENT_ID in your settings.py file

3. Add the `Authorization` Header to all of your REST API request, prefixing JWT to your token::

    `Authorization: JWT <YOUR_TOKEN>`

4. Use the decorator `@token_required` in all views you want to protect (not_ready_yet)

5. That's it
