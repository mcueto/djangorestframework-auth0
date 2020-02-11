Uses cases
---

--
Multiple Clients - Multiples App - One API
-----------
If you wanna to use multiple Auth0 App and/or Clients -for example if you're creating an open API, you can add as much as you want in the **AUTH0.CLIENTS** settings parameter

``` python
AUTH0 = {
  'CLIENTS': {
      'default': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',
          'AUTH0_AUDIENCE': '<YOUR_AUTH0_CLIENT_AUDIENCE>',
          'AUTH0_ALGORITHM': 'RS256',  # default used in Auth0 apps
          'PUBLIC_KEY': default_certificate_publickey',
      },
      'web': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',
          'AUTH0_AUDIENCE': '<YOUR_AUTH0_CLIENT_AUDIENCE>',
          'AUTH0_ALGORITHM': 'RS256',  # default used in Auth0 apps
          'PUBLIC_KEY': web_certificate_publickey',
      },
      'mobile': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',
          'AUTH0_AUDIENCE': '<YOUR_AUTH0_CLIENT_AUDIENCE>',
          'AUTH0_ALGORITHM': 'RS256',  # default used in Auth0 apps
          'PUBLIC_KEY': mobile_certificate_publickey',
      }
  },
  ...
}
```

In order to select one of them when the authentication is needed -a POST request, for example- you need to add a header called **Client-Code** -by default, but you can customize it-.
The names of the clients are **case sensitive**.
