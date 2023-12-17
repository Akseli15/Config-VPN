#!/bin/bash
sudo wg-quick down wg0 >/dev/null 2>&1
config_file="/etc/wireguard/wg0.conf"
key_to_delete="$1"
temp_file=$(mktemp)
delete_peer=0
while IFS= read -r line; do
  if [[ $line == "peer:"* ]]; then
    peer_key=$(echo "$line" | awk '{print $2}')
    if [[ $peer_key == "$key_to_delete" ]]; then
      delete_peer=1
    else
      delete_peer=0
    fi
  fi

  if [[ $delete_peer -eq 0 ]]; then
    echo "$line" >> "$temp_file"
  fi
done < "$config_file"
sudo mv "$temp_file" "$config_file"
rm "$temp_file"
sudo wg-quick up wg0 >/dev/null 2>&1