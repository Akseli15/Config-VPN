from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
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
import ipaddress, random, re, json

#DONE
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

#DONE
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

#DONE
class GetServer(APIView):

    # @jwt_auth_check
    def get(self, _):
        serializer = ServerSerializer(Server.objects.all(), many=True)
        return JsonResponse(serializer.data, safe=False)

#DONE
class GetServerById(APIView):
    #@jwt_auth_check
    def get(self, _, id):
        try:
            server = Server.objects.get(_id=id)
            serverUser = ServerUser.objects.get(_id=id)

            ip = server.ip
            port_ssh = server.portSSH
            username = serverUser.login
            password = serverUser.password

            status_command = [
                'core/backend/scripts/status.sh',
                ip,
                port_ssh,
                username,
                password,
            ]

            try:
                subprocess.run(status_command, check=True)
            except subprocess.CalledProcessError as e:
                return JsonResponse({"error": f"Ошибка при выполнении команды: {e.output}"})
            try:
                output = subprocess.check_output(status_command, text=True)
            except subprocess.CalledProcessError as e:
                return JsonResponse({"error": f"Ошибка при выполнении команды: {e.output}"})

            match = re.search(r'\s*listening port:\s*(\d+)', output)
            listening_port = match.group(1) if match else None

            peer_info = re.findall(r'peer: (\S+)\n(\s+\S+: .+\n)+', output)

            users = []
            for peer in peer_info:
                peer_dict = {}
                peer_dict["public_key"] = peer[0]
                peer_lines = peer[1].strip().split('\n')
                for line in peer_lines:
                    key, value = map(str.strip, line.split(':'))
                    peer_dict[key] = value
                users.append(peer_dict)

            workload = output[0]

            count_of_users = len(users) / (workload / 100) if workload else 0

            if listening_port:
                result_data = {
                    "serverStatus": "Сервер активен",
                    "wg_status": f"WireGuard прослушивает порт {listening_port}",
                    "workload": workload,
                    "total_users": count_of_users,
                    "userCounter": len(users),
                    "users": users
                }
            else:
                result_data = {
                    "serverStatus": "Сервер неактивен",
                }

            return Response(result_data)
        except Server.DoesNotExist:
            return Response({"error": "Сервер не найден"}, status=404)

#DONE
class CreateServer(APIView):
    #@jwt_auth_check
    def post(self, request):
        _id = request.data.get('id')
        ip = request.data.get('ip')
        port_ssh = request.data.get('port_ssh')
        username = request.data.get('username')
        password = request.data.get('password')
        suCommand = request.data.get('suCommand')
        suPassword = request.data.get('suPassword')
        serverUsername = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        serverPassword = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
        port_WG = str(random.randint(49152, 65535))

        create_command = [
            'core/backend/scripts/installing.sh',
            ip,
            port_ssh,
            port_WG,
            username,
            password,
            suCommand,
            suPassword,
            serverUsername,
            serverPassword,
        ]

        try:
            process = subprocess.run(create_command, text=True, check=True, stdout=subprocess.PIPE)
            output = process.stdout
        except subprocess.CalledProcessError as e:
            return JsonResponse({"error": f"Ошибка при выполнении команды: {e.output}"})

        output_lines = output.splitlines()
        public_key = output_lines[0]

        status_command = [
            'core/backend/scripts/status.sh',
            ip,
            port_ssh,
            username,
            password,
        ]

        try:
            subprocess.run(status_command, check=True)
        except subprocess.CalledProcessError as e:
            return JsonResponse({"error": f"Ошибка при выполнении команды: {e.output}"})
        try:
            output = subprocess.check_output(status_command, text=True)
        except subprocess.CalledProcessError as e:
            return JsonResponse({"error": f"Ошибка при выполнении команды: {e.output}"})

        match = re.search(r'\s*listening port:\s*(\d+)', output)
        listening_port = match.group(1) if match else None

        result_status = {}

        if listening_port:
            result_status = {
                "Status": "Сервер успешно создан",
                "ServerStatus": "Сервер активен",
                "WGStatus": "WireGuard прослушивает порт" + listening_port
            }
            statusServer = True
            statusWG = True
        else:
            result_status = {
                "Status": "Ошибка при создании сервера",
                "ServerStatus": "Сервер неактивен"
            }
            statusServer = False
            statusWG = False

        server = Server(_id=_id, ip=ip, portSSH=port_ssh, portWG=port_WG, publicKey=public_key, statusServer=statusServer, statusWG=statusWG)
        server.save()

        serverUser = ServerUser(_id=_id, login=serverUsername, password=serverPassword)
        serverUser.save()
        
        return Response(result_status)


#DONE
class DeleteServer(APIView):

    # @jwt_auth_check
    def get(self, request):
        id = request.data.get('id')

        server = Server.objects.get(_id=id)
        serverUser = ServerUser.objects.get(_id=id)

        server = Server.objects.get(_id=id)
        ip = server.ip
        username = serverUser.login
        password =  serverUser.password
        port_ssh =  server.portSSH

        command = [
            'core/backend/scripts/deleteServer.sh',
            ip,
            port_ssh,
            username,
            password
        ]

        subprocess.run(command)

        server_users = ServerUser.objects.filter(server=server)
        for user in server_users:
            user.delete()
        server.delete()
        serverUser.delete()

        return Response({"Status": "Сервер успешно удалён"})
    
#IN WORK
class CreateUser(APIView):

    # @jwt_auth_check
    def post(self, request):
        _id = request.data.get('_id')
        port_ssh = request.data.get('port_ssh')
        port_WG = request.data.get('port_WG')
        username = request.data.get('username')
        password = request.data.get('password')
        ip = request.data.get('ip')

        server = Server.objects.get(_id=id)

        server_publickey = ServerSerializer(server).publicKey

        vpnip = ipaddress.IPv4Address(random.randint(ipaddress.IPv4Address('10.0.0.1'), ipaddress.IPv4Address('255.255.255.255')))
        ip_with_mask = ipaddress.IPv4Network(f"{vpnip}/32", strict=False)

        command = [
            'core/backend/scripts/addUser.sh',
            ip,
            port_ssh,
            port_WG,
            username,
            password,
            _id,
            ip_with_mask,
            server_publickey
        ]

        subprocess.run(command)
        output = subprocess.check_output(command)
        output_lines = output.decode('utf-8').splitlines()

        public_key = output_lines[0]

        # Script return statusWG instead of statusServer
        status_command = [
            'core/backend/scripts/status.sh',
            ip,
            port_ssh,
            username,
            password,
        ]

        subprocess.run(status_command)

        output = subprocess.check_output(status_command)
        output_status = output.decode('utf-8').splitlines()

        #Write parser
        statusServer = output_status[0]
        statusWG = output_status[1]

        user = User(_id=_id, username = username, publicKey = public_key, allowedIps = ip_with_mask)
        user.save()

        #return just WGstatus
        result_status = {
            "Status":"Пользователь успешно создан",
            "WGStatus": statusWG
        }

        return Response(result_status)


class DeleteUser(APIView):

    # @jwt_auth_check
    def delete(self, request):
        user_id = request.data.get('id')

        user = User.objects.get(_id=user_id)
        publicKey = user.publicKey

        server = Server.objects.get(publicKey=publicKey)
        server_id = server._id

        serverUser = ServerUser.objects.get(_id=server_id)

        ip = server.ip
        port_ssh = server.portSSH
        username = serverUser.login
        password = serverUser.password

        command = [
            'core/backend/scripts/deleteUser.sh',
            ip,
            port_ssh,
            username,
            password,
            publicKey
        ]

        subprocess.run(command)

        return Response({"Status": "Пользователь успешно удалён"})