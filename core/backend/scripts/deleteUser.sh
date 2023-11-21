ip=$1
portSSH=$2
username=$3
password=$4
publicKey=$5

sshpass -p "$password" ssh $username@$ip -p $portSSH "sudo bash ./deleteUser.sh $publicKey"