ip=$1
portSSH=$2
portWG=$3
username=$4
password=$5
id=$6
vpnIp=$7
server_publickey=$8

configsFolder=$(cat ./configsFolder)

mkdir $configsFolder/$ip/keys

wg genkey | tee "$configsFolder/$ip/keys/client_privatekey" | wg pubkey | tee "$configsFolder/$ip/keys/client_publickey"
wg genpsk | tee "$configsFolder/$ip/keys/client_preshared"

client_privatekey=$(cat "$configsFolder/$ip/keys/client_privatekey")
client_publickey=$(cat "$configsFolder/$ip/keys/client_publickey")
client_preshared=$(cat "$configsFolder/$ip/keys/client_preshared")
rm -r $configsFolder/$ip/keys

touch "$configsFolder/$ip/userConfig/$id.conf"
echo "[Interface]
Address = $vpnIp
PrivateKey = $client_privatekey
DNS = 1.1.1.1, 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = $server_publickey
PresharedKey = $client_preshared
PersistentKeepalive = 25
Endpoint = $server_ip:$portWG
AllowedIPs = 0.0.0.0/0, ::/0
" > "$configsFolder/$ip/userConfig/$id.conf"

sshpass -p "$password" ssh $username@$ip -p $portSSH "sudo bash ./createUser.sh $client_publickey $client_preshared $vpnIp"