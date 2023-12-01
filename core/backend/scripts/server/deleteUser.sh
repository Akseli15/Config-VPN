ip=$1
portSSH=$2
username=$3
password=$4
id=$5
publicKey=$6

configsFolder=$(cat ./configsFolder)

sshpass -p "$password" ssh $username@$ip -p $portSSH "sudo bash ./deleteUser.sh $publicKey"
rm $onfigsFolder/$ip/$id.conf