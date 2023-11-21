ip=$1
portSSH=$2
username=$3
password=$4

if ping -c 1 $ip > /dev/null; then
    echo "Сервер $ip доступен"
else
    echo "Сервер $ip недоступен"
    exit 1
fi

sshpass -p "$password" ssh $username@$ip -p $portSSH "bash ./status.sh"