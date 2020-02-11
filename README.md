djangorestframework-auth0
=====
___

This library let you to **authenticate** an specific user on DRF based on the JWT Token returned by Auth0 Javascript libraries.

![Logo](docs/logo.png)

Installation
-----------

1. Using `pip` install the library cloning the repository with following command:
``` shell
pip install rest_framework_auth0
```

Quick start
-----------

1. Make sure "django.contrib.auth in on INSTALLED_APPS setting, otherwise add it by your own:
``` python
INSTALLED_APPS = [
    ...
    'django.contrib.auth',
    ...
]
```
This will allow us to login as an specific user as well as auto-creating users when they don't exist

1. Add "rest_framework_auth0" to your INSTALLED_APPS **after** `rest_framework_jwt` setting like this:
``` python
INSTALLED_APPS = [
    ...,
    'rest_framework_auth0',
]
```

2. Add `Auth0JSONWebTokenAuthentication` in your DEFAULT_AUTHENTICATION_CLASSES located at settings.py from your project:
``` python
REST_FRAMEWORK = {
    ...,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...,
        'rest_framework_auth0.authentication.Auth0JSONWebTokenAuthentication',
    ),
}
```

3. Add your CLIENTS setting in your settings.py file:
``` python
AUTH0 = {
  'CLIENTS': {
      'default': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',
          'AUTH0_AUDIENCE': '<YOUR_AUTH0_CLIENT_AUDIENCE>',
          'AUTH0_ALGORITHM': 'RS256',  # default used in Auth0 apps
          'PUBLIC_KEY': '<YOUR_CERTIFICATE_FILE_PUBLIC_KEY>',
      }
  },
  # Management API - For roles and permissions validation
  'MANAGEMENT_API': {
      'AUTH0_DOMAIN': '<YOUR_AUTH0_DOMAIN>',
      'AUTH0_CLIENT_ID': '<YOUR_AUTH0_M2M_API_MANAGEMENT_CLIENT_ID>',
      'AUTH0_CLIENT_SECRET': '<YOUR_AUTH0_M2M_API_MANAGEMENT_CLIENT_SECRET>'
  },
}
```

4. Add the `Authorization` Header to all of your REST API request, prefixing JWT to your token:
```
Authorization: JWT <AUTH0_GIVEN_TOKEN>
```
5. Use the decorator `@token_required` in all views you want to protect (not_ready_yet)

6. That's it

```
NOTE: In order to get the token authentication, the 'django.contrib.auth' app models migrations must be applied(python manage.py migrate).
```

Multiple Clients - Multiples App - One API
-----------
If you wanna to use multiple Auth0 App and/or Clients -for example if you're creating an open API, you can add as much as you want in the **AUTH0.CLIENTS** settings parameter

``` python
AUTH0 = {
  'CLIENTS': {
      'default': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',  #make sure it's the same string that aud attribute in your payload provides
          'AUTH0_CLIENT_SECRET': '<YOUR_AUTH0_CLIENT_SECRET>',
          'CLIENT_SECRET_BASE64_ENCODED': True,  # default to True, if you're Auth0 user since December, maybe you should set it to False
          'AUTH0_ALGORITHM': 'HS256',
      }
      'web': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',  #make sure it's the same string that aud attribute in your payload provides
          'AUTH0_CLIENT_SECRET': '<YOUR_AUTH0_CLIENT_SECRET>',
          'CLIENT_SECRET_BASE64_ENCODED': True,  # default to True, if you're Auth0 user since December, maybe you should set it to False
          'AUTH0_ALGORITHM': 'HS256',
      }
      'mobile': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',  #make sure it's the same string that aud attribute in your payload provides
          'AUTH0_CLIENT_SECRET': '<YOUR_AUTH0_CLIENT_SECRET>',
          'CLIENT_SECRET_BASE64_ENCODED': True,  # default to True, if you're Auth0 user since December, maybe you should set it to False
          'AUTH0_ALGORITHM': 'HS256',
      }
  },
  ...
}
```

In order to select one of them when the authentication is needed -a POST request, for example- you need to add a header called **Client-Code** -by default, but you can customize it-.
The names of the clients are **case sensitive**.


Migrations
---
- [Migrate from 0.2.1 to > 0.4.5](docs/migrations.md)

RS256 Support
---
If you wanna use RS256, please follow the Sample Project

Sample Project
-----------
A sample project can be found [here][sample]

[sample]: https://github.com/mcueto/djangorestframework-auth0_sample
