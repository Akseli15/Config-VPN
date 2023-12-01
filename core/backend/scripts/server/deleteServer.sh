serverIp=$1
portSSH=$2
username=$3
password=$4
suCommand=$6
suPassword=$7

configsFolder=$(cat ./configsFolder)
shellFolder=$(pwd)

rm -r  $configsFolder/$serverIp