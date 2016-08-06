from distutils.core import setup
setup(
  name = 'rest_framework_auth0',
  packages = ['rest_framework_auth0'],
  version = '0.1.1',
  description = 'Django Rest Framework Library to use Auth0 authentication',
  author = 'Marcelo Cueto',
  author_email = 'yo@marcelocueto.cl',
  url = 'https://github.com/mcueto/djangorestframework-auth0',
  download_url = 'https://github.com/mcueto/djangorestframework-auth0/tarball/0.1',
  keywords = ['auth0', 'rest framework', 'django'],
  classifiers=[
      'Environment :: Web Environment',
      'Framework :: Django',
      'Intended Audience :: Developers',
      'License :: OSI Approved :: MIT License',
      'Operating System :: OS Independent',
      'Programming Language :: Python',
      'Programming Language :: Python :: 3',
      'Programming Language :: Python :: 3.4',
      'Programming Language :: Python :: 3.5',
      'Topic :: Internet :: WWW/HTTP',
  ],
  install_requires = [
      'djangorestframework>=1.9.0',
      'djangorestframework-jwt>=1.7.2',
      'django-filter',
  ],
)
