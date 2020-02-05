import logging
from rest_framework import serializers
from django.contrib.auth.models import Group

logger = logging.getLogger(__name__)


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group


class GroupsSerializerMixin(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)
