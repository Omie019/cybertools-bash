#!/bin/bash

# Simple Network Traffic Analyzer (SNTA) with net-tools Installation Support

# Function to check if a command/tool is available
check_and_install_tool() {
    TOOL=$1
    PACKAGE=$2
    if ! command -v "$TOOL" &> /dev/null; then
        echo "$TOOL is not installed."
        read -p "Do you want to install $PACKAGE (required for $TOOL)? (yes/no): " choice
        if [[ "$choice" == "yes" ]]; then
            echo "Installing $PACKAGE..."
            sudo apt update
            sudo apt install -y "$PACKAGE"
            if command -v "$TOOL" &> /dev/null; then
                echo "$TOOL successfully installed."
            else
                echo "Failed to install $TOOL. Please install it manually and retry."
                exit 1
            fi
        else
            echo "Cannot proceed without $TOOL. Exiting."
            exit 1
        fi
    fi
}

# Function to show active network connections
show_active_connections() {
    check_and_install_tool "netstat" "net-tools"
    echo "---------------------------------------------"
    echo "Active Network Connections"
    echo "---------------------------------------------"
    netstat -ant | awk 'NR>2 {print $1, $4, $5, $6}' | column -t
}

# Function to monitor packet statistics
monitor_packet_stats() {
    check_and_install_tool "cat" "coreutils"
    echo "---------------------------------------------"
    echo "Packet Statistics (Incoming and Outgoing)"
    echo "---------------------------------------------"
    RX_BYTES=$(cat /sys/class/net/eth0/statistics/rx_bytes)
    TX_BYTES=$(cat /sys/class/net/eth0/statistics/tx_bytes)
    echo "Received Bytes: $RX_BYTES"
    echo "Transmitted Bytes: $TX_BYTES"
}

# Function to detect unusual ports
detect_unusual_ports() {
    check_and_install_tool "netstat" "net-tools"
    echo "---------------------------------------------"
    echo "Unusual Open Ports (Listening)"
    echo "---------------------------------------------"
    netstat -tuln | awk '{print $4}' | grep ':' | cut -d':' -f2 | sort | uniq -c | while read line; do
        PORT=$(echo $line | awk '{print $2}')
        if [ $PORT -gt 1024 ]; then
            echo "Port $PORT is open (high number port)"
        fi
    done
}

# Function to log network traffic usage
log_traffic_usage() {
    check_and_install_tool "date" "coreutils"
    LOG_FILE="traffic_log.txt"
    echo "---------------------------------------------"
    echo "Logging Network Traffic Usage to $LOG_FILE"
    echo "---------------------------------------------"
    RX=$(cat /sys/class/net/eth0/statistics/rx_bytes)
    TX=$(cat /sys/class/net/eth0/statistics/tx_bytes)
    echo "$(date): Received=$RX bytes, Transmitted=$TX bytes" >> $LOG_FILE
    echo "Logged successfully!"
}

# Function to analyze network anomalies
analyze_anomalies() {
    check_and_install_tool "netstat" "net-tools"
    check_and_install_tool "grep" "grep"
    echo "---------------------------------------------"
    echo "Analyzing Potential Network Anomalies"
    echo "---------------------------------------------"
    netstat -ant | grep -v "ESTABLISHED" | awk '{print $5}' | while read line; do
        IP=$(echo $line | cut -d':' -f1)
        echo "Unusual activity detected from IP: $IP"
    done
}

# Main Menu
while true; do
    echo "---------------------------------------------"
    echo "Simple Network Traffic Analyzer (SNTA)"
    echo "1. Show Active Network Connections"
    echo "2. Monitor Packet Statistics"
    echo "3. Detect Unusual Open Ports"
    echo "4. Log Network Traffic Usage"
    echo "5. Analyze Network Anomalies"
    echo "6. Exit"
    echo "---------------------------------------------"
    read -p "Choose an option: " choice

    case $choice in
        1) show_active_connections ;;
        2) monitor_packet_stats ;;
        3) detect_unusual_ports ;;
        4) log_traffic_usage ;;
        5) analyze_anomalies ;;
        6) echo "Exiting..."; break ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done

