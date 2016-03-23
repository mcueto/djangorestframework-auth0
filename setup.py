import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='rest_framework_auth0',
    version='0.0.1',
    # packages=find_packages(),
    # include_package_data=True,
    license='MIT',
    description='Library to simply use Auth0 token authentication in DRF within djangorestframework-jwt.',
    # long_description=README,
    url='https://github.com/mcueto/djangorestframework-auth0',
    author='Marcelo Cueto',
    author_email='yo@marcelocueto.cl',
    # classifiers=[
    #     'Environment :: Web Environment',
    #     'Framework :: Django',
    #     'Framework :: Django :: X.Y',  # replace "X.Y" as appropriate
    #     'Intended Audience :: Developers',
    #     'License :: OSI Approved :: BSD License',  # example license
    #     'Operating System :: OS Independent',
    #     'Programming Language :: Python',
    #     # Replace these appropriately if you are stuck on Python 2.
    #     'Programming Language :: Python :: 3',
    #     'Programming Language :: Python :: 3.4',
    #     'Programming Language :: Python :: 3.5',
    #     'Topic :: Internet :: WWW/HTTP',
    #     'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    # ],
    install_requires = [
        'djangorestframework-jwt>=1.7.2',
    ],
)
