#!/bin/bash

# Configuration
INTERFACE="eth0"  # Network interface to monitor
THRESHOLD_MBPS=50  # Threshold to activate XDP filtering (in Mbps)
CAPTURE_DURATION="60"  # Capture time (in seconds)
LOG_FILE="attack_log.txt"
CAPTURE_FILE="attack_traffic.pcap"
XDP_OBJ="xdp_filter.o"  # Compiled XDP program object file
DISCORD_WEBHOOK_URL="YOUR_DISCORD_WEBHOOK_URL"

# Static terminal interface initialization
initialize_terminal_interface() {
    tput clear
    tput cup 0 0
    echo "--------------------------------------------------------"
    echo "| Real-Time DDoS Monitoring - Attack Detection System   |"
    echo "--------------------------------------------------------"
    echo "| Traffic Rate (Mbps) | Action                         |"
    echo "--------------------------------------------------------"
}

# Update the static terminal interface with traffic rate and action
update_terminal_interface() {
    local mbps=$1
    local action=$2
    tput cup 4 0
    printf "| %-19s | %-30s |\n" "$mbps Mbps" "$action"
    echo "--------------------------------------------------------"
}

# Compile XDP program if not already compiled
compile_xdp_program() {
    if [ ! -f "$XDP_OBJ" ]; then
        echo "Compiling XDP program..."
        clang -O2 -target bpf -c xdp_filter.c -o $XDP_OBJ
        if [ $? -ne 0 ]; then
            echo "Error: Failed to compile XDP program."
            exit 1
        fi
    fi
}

# Function to monitor traffic in real-time and detect attacks based on Mbps
monitor_traffic() {
    echo "Monitoring traffic for potential DDoS attacks..."
    initialize_terminal_interface

    while true; do
        # Use tshark to calculate traffic rate in Mbps
        mbps=$(tshark -i $INTERFACE -a duration:1 -q -z io,stat,1 2>/dev/null | grep '<>' | awk '{print $6 / 1000000}')

        # Ensure mbps is a valid number
        if [[ -z "$mbps" || "$mbps" == "nan" || ! "$mbps" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            mbps=0
        fi

        # If the traffic exceeds the threshold, trigger the attack response
        if (( $(echo "$mbps >= $THRESHOLD_MBPS" | bc -l 2>/dev/null) )); then
            update_terminal_interface "$mbps" "Large attack detected! Activating XDP filtering..."
            echo "$(date) - Large attack detected with traffic rate: $mbps Mbps" >> $LOG_FILE
            activate_xdp_filter
            update_terminal_interface "$mbps" "XDP filter active."

            # Capture traffic during attack
            capture_traffic

            # Analyze pcap for attack details
            analyze_pcap "$mbps"

            # Apply iptables rules
            apply_iptables_rules

            # Send Discord notification
            send_discord_notification

            update_terminal_interface "$mbps" "Attack mitigated, rules applied."
        else
            update_terminal_interface "$mbps" "Normal traffic"
        fi

        # Sleep for a short time to reduce CPU usage
        sleep 5
    done
}

# Function to activate XDP filter
activate_xdp_filter() {
    echo "Activating XDP filter..."
    compile_xdp_program
    ip link set dev $INTERFACE xdp obj $XDP_OBJ sec xdp_filter
}

# Function to deactivate XDP filter
deactivate_xdp_filter() {
    echo "Deactivating XDP filter..."
    ip link set dev $INTERFACE xdp off
}

# Function to capture traffic during an attack
capture_traffic() {
    echo "Capturing traffic for $CAPTURE_DURATION seconds..."
    tshark -i $INTERFACE -w $CAPTURE_FILE -a duration:$CAPTURE_DURATION -q 2>/dev/null

    if [ ! -f $CAPTURE_FILE ]; then
        echo "Error: $CAPTURE_FILE not created."
        exit 1
    fi
}

# Analyze pcap file for attack details
analyze_pcap() {
    echo "Analyzing captured traffic for attack details..."
    attack_info=$(tshark -r $CAPTURE_FILE -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -e frame.len -e frame.time_relative -E header=y -E separator=, | head -n 1)

    src_ip=$(echo "$attack_info" | awk -F',' '{print $1}')
    dst_ip=$(echo "$attack_info" | awk -F',' '{print $2}')
    dst_port=$(echo "$attack_info" | awk -F',' '{print $3}')
    if [ -z "$dst_port" ]; then
        dst_port=$(echo "$attack_info" | awk -F',' '{print $4}')
    fi
    frame_len=$(echo "$attack_info" | awk -F',' '{print $5}')
    attack_duration=$(echo "$attack_info" | awk -F',' '{print $6}')

    echo "Attack detected from $src_ip to $dst_ip on port $dst_port. Frame size: $frame_len bytes. Duration: $attack_duration seconds." >> $LOG_FILE
}

# Function to apply iptables rules based on attack analysis
apply_iptables_rules() {
    echo "Applying iptables rules..."
    # Example: Blocking the attacking IP or port (could be further customized)
    iptables -A INPUT -s $src_ip -j DROP
    iptables -A INPUT -p tcp --dport $dst_port -j DROP
    iptables -A INPUT -p udp --dport $dst_port -j DROP
    echo "iptables rules applied to block $src_ip on port $dst_port."
}

# Function to send a notification to Discord with attack details
send_discord_notification() {
    echo "Sending Discord notification..."

    # Prepare Discord notification payload
    discord_payload=$(printf '{
      "embeds": [
        {
          "title": "DDoS Attack Detected",
          "color": 15158332,
          "fields": [
            {
              "name": "Source IP",
              "value": "%s",
              "inline": true
            },
            {
              "name": "Destination IP",
              "value": "%s",
              "inline": true
            },
            {
              "name": "Destination Port",
              "value": "%s",
              "inline": true
            },
            {
              "name": "Frame Size",
              "value": "%s bytes",
              "inline": true
            },
            {
              "name": "Duration",
              "value": "%s seconds",
              "inline": true
            },
            {
              "name": "Hex Data",
              "value": "```\n%s\n```",
              "inline": false
            }
          ],
          "footer": {
            "text": "DDoS Protection System"
          }
        }
      ]
    }' "$src_ip" "$dst_ip" "$dst_port" "$frame_len" "$attack_duration" "$(hexdump -C $CAPTURE_FILE | head -n 10)")

    # Send payload to Discord webhook
    curl -H "Content-Type: application/json" -X POST -d "$discord_payload" "$DISCORD_WEBHOOK_URL"
}

# Start monitoring traffic
monitor_traffic
