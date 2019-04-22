Migrations
---

## Migrate from 0.2.1 to > 0.4.5

**If you're using the version 0.2.1 -or older- from this package, you'll need to update your Auth0 settings**

From this
``` python
AUTH0 = {
    'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>', # make sure it's the same string that aud attribute in your payload provides
    'AUTH0_CLIENT_SECRET': '<YOUR_AUTH0_CLIENT_SECRET>',
    'CLIENT_SECRET_BASE64_ENCODED': True,  # default to True, if you're Auth0 user since December, maybe you should set it to False
    ...
}

```

To this
``` python
AUTH0 = {
  'CLIENTS': {
      'default': {
          'AUTH0_CLIENT_ID': '<YOUR_AUTH0_CLIENT_ID>',  #make sure it's the same string that aud attribute in your payload provides
          'AUTH0_CLIENT_SECRET': '<YOUR_AUTH0_CLIENT_SECRET>',
          'CLIENT_SECRET_BASE64_ENCODED': False,  # default to True, if you're Auth0 user since December 2016, you should set it to False,
          'AUTH0_ALGORITHM': 'HS256',  # HS256 or RS256
          'PUBLIC_KEY': <YOUR_AUTH0_CERTIFICATE>,  # used only for RS256
      }
  },
  ...
}
```
