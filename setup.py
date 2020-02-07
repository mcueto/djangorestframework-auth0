from setuptools import setup
from os import path


# Read the README.md file content
def get_long_description(filename='README.md'):
    this_directory = path.abspath(path.dirname(__file__))
    with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name='rest_framework_auth0',
    packages=['rest_framework_auth0'],
    include_package_data=True,
    version='0.5.3',
    description='Django Rest Framework Library to use Auth0 authentication',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    author='Marcelo Cueto',
    author_email='cueto@live.cl',
    url='https://github.com/mcueto/djangorestframework-auth0',
    download_url='https://github.com/mcueto/djangorestframework-auth0/tarball/0.5.3',
    keywords=['auth0', 'rest framework', 'django'],
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
    install_requires=[
        'django>=1.10.0',
        'djangorestframework>=1.9.0',
        'djangorestframework-jwt>=1.7.2',
        'cryptography',
    ],
)
