pubkey=$1
presharedKey=$2
vpnIp=$3

sudo wg-quick down wg0

sudo echo "[Peer]
PublicKey = $pubkey
PresharedKey = $presharedKey
AllowedIPs = $vpnIp
" >> /etc/wireguard/wg0.conf

sudo wg-quick up wg0

sudo wg