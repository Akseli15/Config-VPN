from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from apps.authentication import jwt_auth_check
from .serializer import *
from .models import *

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
import random, string, subprocess
import ipaddress, random


class AuthToken(APIView):
    
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def post(self, request):
        username = request.data.get('login')
        password = request.data.get('password')

        if not username or not password:
            return Response({"error": "Username and password are required."})

        user = authenticate(username=username, password=password)
        if not user:
            return Response({"error": "Invalid credentials."})

        token = get_tokens_for_user(user)
        serializer = UserSerializer(user)
        return Response({"user": {"last_login": serializer.data.get("last_login"), "email": serializer.data.get("email")}, "refresh_token": token['refresh'], "access_token": token['access']})
    
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class Logout(APIView):

    permission_classes = (IsAuthenticated,)
    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class GetServer(APIView):

    @jwt_auth_check
    def get(self, _):
        serializer = ServerSerializer(Server.objects.all(), many=True)
        return JsonResponse(serializer.data, safe=False)

class CreateServer(APIView):

    @jwt_auth_check
    def post(self, request):
        _id = request.data.get('id')
        ip = request.data.get('ip')
        port_ssh = request.data.get('port_ssh')
        username = request.data.get('username')
        password = request.data.get('password')
        suCommand = request.data.get('suCommand')
        serverUsername = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        serverPassword = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
        port_WG = str(random.randint(1024, 65535))

        create_command = [
            'bash',
            'core/backend/scripts/installing.sh',
            ip,
            port_ssh,
            port_WG,
            username,
            password,
            suCommand,
            'not_vpn_at_all',
            serverUsername,
            serverPassword,
        ]

        subprocess.run(create_command)

        output = subprocess.check_output(create_command)
        output_lines = output.decode('utf-8').splitlines()

        public_key = output_lines[0]
        # private_key = output_lines[1]

        status_command = [
            'bash',
            'core/backend/scripts/status.sh',
            ip,
            port_ssh,
            username,
            password,
        ]
        
        subprocess.run(status_command)

        output = subprocess.check_output(status_command)
        output_status = output.decode('utf-8').splitlines()
        statusServer = output_status[0]
        statusWG = output_status[1]

        server = Server(_id=_id, ip=ip, portSSH=port_ssh, portWG = port_WG, publicKey = public_key, statusServer = statusServer, statusWG = statusWG)
        server.save()

        return Response({"status": "ok"})

class DeleteServer(APIView):

    @jwt_auth_check
    def delete(self, request):
        serverIp = request.data.get('serverIp')
        username = request.data.get('username')
        password = request.data.get('password')
        port_ssh = request.data.get('port_ssh')

        server = get_object_or_404(Server, pk=serverIp)

        command = [
            'bash',
            'core/backend/scripts/deleteServer.sh',
            serverIp,
            port_ssh,
            username,
            password
        ]

        subprocess.run(command)

        server_users = ServerUser.objects.filter(server=server)
        for user in server_users:
            user.delete()
        server.delete()

        return Response({"status": "ok"})
    
class GetUser(APIView):

    @jwt_auth_check
    def get(self, _):
        serializer = UserSerializer(User.objects.all(), many=True)
        return JsonResponse(serializer.data, safe=False)
    
class CreateUser(APIView):

    @jwt_auth_check
    def post(self, request):
        _id = request.data.get('_id')
        port_ssh = request.data.get('port_ssh')
        port_WG = request.data.get('port_WG')
        username = request.data.get('username')
        password = request.data.get('password')
        vpnip = request.data.get('vpnip')
        server_publickey = request.data.get('server_publickey')

        ip = ipaddress.IPv4Address(random.randint(ipaddress.IPv4Address('10.0.0.1'), ipaddress.IPv4Address('255.255.255.255'))) 
        ip_with_mask = ipaddress.IPv4Network(f"{ip}/32", strict=False)

        command = [
            'bash',
            'core/backend/scripts/addUser.sh',
            ip_with_mask,
            port_ssh,
            port_WG,
            username,
            password,
            _id,
            vpnip,
            server_publickey
        ]

        subprocess.run(command)
        output = subprocess.check_output(command)
        output_lines = output.decode('utf-8').splitlines()
        
        public_key = output_lines[0]
        # private_key = output_lines[1]

        status_command = [
            'bash',
            'core/backend/scripts/status.sh',
            ip,
            port_ssh,
            username,
            password,
        ]
        
        subprocess.run(status_command)

        output = subprocess.check_output(status_command)
        output_status = output.decode('utf-8').splitlines()
        statusServer = output_status[0]
        statusWG = output_status[1]

        user = Server(_id=_id, username = username, publicKey = public_key, allowedIps = ip_with_mask)
        user.save()

        return Response({"status": "ok"})
    
class DeleteUser(APIView):

    @jwt_auth_check
    def delete(self, request, id):
        server_id = request.data.get('server_id')
        user_id = request.data.get('user_id')
        server = get_object_or_404(Server, pk=server_id)
        user = get_object_or_404(User, pk=user_id)

        # Проверяем возможность операции и выполняем скрипт deleteUser.sh с требуемыми параметрами
        # Дожидаемся завершения выполнения скрипта и получаем результаты (например, 3 параметра)
        # В зависимости от состояния сервера и статуса операции, удаляем или сохраняем данные в базе данных
        # Возвращаем статус фронтенду
        return Response({"status": "ok"})


class ServerStatus(APIView):

    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # Получаем данные от фронтенда, например, id сервера
        server_id = request.data.get('server_id')

        # Находим объект сервера и связанных с ним пользователей в базе данных
        server = get_object_or_404(Server, pk=server_id)
        server_users = ServerUser.objects.filter(server=server)

        # Выполняем скрипт status.sh с требуемыми параметрами
        # Парсим данные, такие как статус сервера, загрузка CPU, статус VPN, последний онлайн пользователя и т. д.
        # Сохраняем и выводим необходимые данные на фронтенд
        # Проверяем список клиентов и обновляем базу данных в соответствии с результатами
        # ...
        # Возвращаем статус фронтенду
        return Response({"status": "ok"})
