from rest_framework import serializers
from django.contrib.auth.models import Group

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group

class GroupsSerializerMixin(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)
