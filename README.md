djangorestframework-auth0
=====
___

This library let you to **authenticate** an specific user on DRF based on the JWT Token returned by Auth0 Javascript libraries.

![Logo](docs/logo.png)

Installation
-----------

1. Using `pip` to install current release:
``` shell
pip install rest_framework_auth0
```

2. Using `pip` to install development version:
``` shell
pip install git+https://github.com/mcueto/djangorestframework-auth0/
```


Quick start
-----------

1. Make sure `django.contrib.auth` in on INSTALLED_APPS setting, otherwise add it by your own:
``` python
INSTALLED_APPS = [
    ...
    'django.contrib.auth',
    ...
]
```
This will allow us to login as an specific user as well as auto-creating users when they don't exist

1. Add `rest_framework_auth0` to your `INSTALLED_APPS` setting:
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

3. Add your `CLIENTS` & `MANAGEMENT_API` settings in your settings.py file:
```python
# Import cryptography libraries
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
# Read the your Auth0 client PEM certificate
certificate_text = open('rsa_certificates/certificate.pem', 'rb').read()
certificate = load_pem_x509_certificate(certificate_text, default_backend())
# Get your PEM certificate public_key
certificate_publickey = certificate.public_key()
#
#
# AUTH0 SETTINGS
AUTH0 = {
  'CLIENTS': {
      'default': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',
          'AUTH0_AUDIENCE': '<YOUR_AUTH0_CLIENT_AUDIENCE>',
          'AUTH0_ALGORITHM': 'RS256',  # default used in Auth0 apps
          'PUBLIC_KEY': certificate_publickey',
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

4. Add the `Authorization` Header to all of your REST API request, prefixing `Bearer` to your token(default in common REST clients & Postman):
```
Authorization: Bearer <AUTH0_GIVEN_TOKEN>
```

5. That's it, now only your Auth0 users can request data to your DRF endpoints

```
NOTE: In order to get the token authentication, the 'django.contrib.auth' app models migrations must be applied(python manage.py migrate).
```

Use cases
-----------
- [Use cases can be found here](docs/use_cases.md)

Sample Project
-----------
A sample project can be found [here][sample]

[sample]: https://github.com/mcueto/djangorestframework-auth0_sample
