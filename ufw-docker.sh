#!/bin/bash

# Define the container name
container_name="intelowl_nginx"
# Define the array of external IPs that need access
external_ips=("128.230.49.121" "128.230.67.26") # Add more IPs as needed
# Define the port you want to allow access to
port="80"

# Function to delete existing firewall rules
delete_firewall_rules() {
  local from_ip=$1
  local container_ip=$2
  local port=$3

  echo "Deleting existing firewall rules for $from_ip accessing $container_ip on port $port"

  # Delete existing rule if it exists
  sudo ufw route delete proto tcp from $from_ip to $container_ip port $port
}

# Function to apply firewall rules
apply_firewall_rules() {
  local from_ip=$1
  local container_ip=$2
  local port=$3

  echo "Applying firewall rules for $from_ip to access $container_ip on port $port"

  # Add new rule
  sudo ufw route allow proto tcp from $from_ip to $container_ip port $port
}

# Fetch the current container IP
container_ip=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $container_name)

# Loop through each external IP and delete existing firewall rules
for from_ip in "${external_ips[@]}"; do
  delete_firewall_rules $from_ip $container_ip $port
done

# Loop through each external IP and apply new firewall rules
for from_ip in "${external_ips[@]}"; do
  apply_firewall_rules $from_ip $container_ip $port
done
