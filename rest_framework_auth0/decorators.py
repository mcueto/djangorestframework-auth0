import json
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework_auth0.settings import auth0_api_settings

def json_response(response_dict, status=200):
    response = HttpResponse(json.dumps(response_dict), content_type="application/json", status=status)
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


"""
TODO: Verify if the token is valid and not expired(need to decode before verify)
"""

from django.views.generic.base import TemplateView
from django.utils.decorators import method_decorator
from functools import wraps
from rest_framework import exceptions
from rest_framework_auth0.authentication import jwt_decode_handler
from rest_framework_auth0.utils import get_jwt_value, get_roles_from_payload

class token_required(object):

    def __init__(self, view_func):
        self.view_func = view_func
        wraps(view_func)(self)

    def __call__(self, request, *args, **kwargs):
        # maybe do something before the view_func call
        # print(request.method)
        # print ("----hello")

        if request.method == 'OPTIONS':
            return func(request, *args, **kwargs)

        auth_header = request.META.get('HTTP_AUTHORIZATION', None)

        if auth_header is not None:
            tokens = auth_header.split(' ')

            if len(tokens) == 2 and tokens[0] == auth0_api_settings.JWT_AUTH_HEADER_PREFIX :
                token = tokens[1]
                #get called view
                response = self.view_func(request, *args, **kwargs)
            else:
                response = json_response({"msg":"Not valid token"}, status=401)

        # maybe do something after the view_func call
        # print ("----bye")
        return response

class is_authenticated(object):

    def __init__(self, view_func):
        self.view_func = view_func
        wraps(view_func)(self)

    def __call__(self, request, *args, **kwargs):
        # maybe do something before the view_func call
        # print(request.method)
        # print ("----hello")

        if request.method == 'OPTIONS':
            return func(request, *args, **kwargs)

        if request.user.is_authenticated():
            #get called view
            response = self.view_func(request, *args, **kwargs)
        else:
            response = json_response({"msg":"Not authenticated"}, status=401)

        # maybe do something after the view_func call
        # print ("----bye")
        return response

class with_role(object):

    def __init__(self, view_func):
        self.view_func = view_func
        wraps(view_func)(self)

    def __call__(self, request, *args, **kwargs):
        # maybe do something before the view_func call
        # print(request.method)
        # print ("----hello")
        if request.method == 'OPTIONS':
            return func(request, *args, **kwargs)

        jwt = get_jwt_value(request)

        try:
            payload = jwt_decode_handler(jwt)

            roles = get_roles_from_payload(payload)

            if(len(roles)>0):
                # get called view
                response = self.view_func(request, *args, **kwargs)
            else:
                response = json_response({"msg":"User has no roles"}, status=401)

        except Exception as e:
            response = json_response({"msg":str(e)}, status=401)
            # pass

        # maybe do something after the view_func call
        # print ("----bye")
        return response
