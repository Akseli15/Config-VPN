serverIp=$1
portWG=$2

sudo touch /etc/wireguard/wg0.conf
mkdir keys
wg genkey | tee "$PWD/keys/server_privatekey" | wg pubkey | tee "$PWD/keys/server_publickey"
server_privatekey=$(cat "$PWD/keys/server_privatekey")
server_publickey=$(cat "$PWD/keys/server_publickey")
echo "$server_privatekey"
rm -r keys

server_interface=$(ip route | grep default | awk '{print $5}')

sudo echo "[Interface]
PrivateKey = $server_privatekey
Address = $serverIp
SaveConfig = true
PostUp = iptables -t nat -I POSTROUTING -o $server_interface -j MASQUERADE
PostUp = ip6tables -t nat -I POSTROUTING -o $server_interface -j MASQUERADE
PostUp = ufw allow $portWG/udp
PreDown = iptables -t nat -D POSTROUTING -o $server_interface -j MASQUERADE
PreDown = ip6tables -t nat -D POSTROUTING -o $server_interface -j MASQUERADE
PreDown = ufw delete allow $portWG/udp
ListenPort = $portWG
">>/etc/wireguard/wg0.conf