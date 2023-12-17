#testdata: 10.10.10.10 22 64000 user useruser sudo adminadmin wguser wireguard

configsFolder=$(cat ./configsFolder)
shellFolder=$(pwd)

serverIp=$1
portSSH=$2
portWG=$3
username=$4
password=$5
suCommand=$6 
suPassword=$7
serverUsername=$8
serverPassword=$9

mkdir $configsFolder/$serverIp
mkdir $configsFolder/$serverIp/vpn
mkdir $configsFolder/$serverIp/userConfig/
mkdir $configsFolder/$serverIp/vpn/shell
cp $shellFolder/server/* $configsFolder/$serverIp/vpn/shell

sshpass -p "$password" scp -o StrictHostKeyChecking=no -P $portSSH -r $configsFolder/$serverIp/vpn/ $username@$serverIp:/tmp/
sshpass -p "$password" ssh -o StrictHostKeyChecking=no $username@$serverIp -p $portSSH 'bash -s' << EOF
echo '$suPassword' | $suCommand -S mkdir /vpn
$suCommand cp -r /tmp/vpn/* /vpn
$suCommand bash /vpn/shell/install.sh $serverUsername $serverPassword $serverIp $portSSH $portWG
EOF

rm -r  $configsFolder/$serverIp/vpn