#!/bin/bash

# Define the container name
container_name="intelowl_nginx"
# Define the array of external IPs that need access
external_ips=("128.230.49.121" "129.230.67.26") # Add more IPs as needed
# Define the port you want to allow access to
port="80"

# Fetch the current container IP
container_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $container_name)

# Function to apply firewall rules
apply_firewall_rules() {
  local from_ip=$1
  local container_ip=$2
  local port=$3

  # Check if IP is within the expected subnet (optional, for safety)
  if [[ $container_ip =~ ^172\.19\. ]]; then
    echo "Applying firewall rules for $from_ip to access $container_ip on port $port"
    
    # Add new rule
    sudo ufw route allow proto tcp from $from_ip to $container_ip port $port
  else
    echo "Error: Container IP ($container_ip) is not within the expected subnet."
  fi
}

# Loop through each external IP and apply firewall rules
for from_ip in "${external_ips[@]}"; do
  apply_firewall_rules $from_ip $container_ip $port
done
