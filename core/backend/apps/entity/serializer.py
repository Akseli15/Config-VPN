from  rest_framework import serializers
from .models import *

class ServerSerializer(serializers.ModelSerializer):

    class Meta:
        model = Server
        exclude = ['id', ]

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        exclude = ['id', ]

class SystemUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = SystemUser
        exclude = ['id', ]

class ServerUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = ServerUser
        exclude = ['id', ]     