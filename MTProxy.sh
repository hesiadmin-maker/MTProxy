#!/bin/bash

set -euo pipefail

# Constants
readonly SCRIPT_NAME="MTProxy Auto-Healing Installer"
readonly SCRIPT_VERSION="2.1.0"

# Fix for BASH_SOURCE issue when piped to bash
if [[ "${BASH_SOURCE[0]:-}" ]]; then
    readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    readonly SCRIPT_DIR="$(pwd)"
fi

readonly MT_PROXY_DIR="/opt/MTProxy"
readonly CONFIG_FILE="${MT_PROXY_DIR}/objs/bin/mtconfig.conf"
readonly SERVICE_FILE="/etc/systemd/system/MTProxy.service"
readonly MONITOR_SCRIPT="/usr/local/bin/mtproxy-monitor.sh"
readonly MONITOR_SERVICE="/etc/systemd/system/mtproxy-monitor.service"
readonly MONITOR_LOG="/var/log/mtproxy-monitor.log"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
declare -a SECRET_ARRAY=()
declare -i PORT=443
declare -i CPU_CORES=1
declare TAG=""
declare TLS_DOMAIN="www.cloudflare.com"
declare CUSTOM_ARGS=""
declare PUBLIC_IP=""
declare PRIVATE_IP=""
declare HAVE_NAT="n"
declare ENABLE_UPDATER="y"
declare ENABLE_BBR="y"
declare AUTO_INSTALL=false

# Monitoring Configuration
declare ENABLE_MONITORING="y"
declare -i MAX_PIDS=1000
declare -i MAX_MEMORY_PERCENT=80
declare -i MAX_CPU_PERCENT=90
declare -i CHECK_INTERVAL=300
declare -i MAX_RESTARTS=3
declare -i RESTART_WINDOW=3600

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Utility functions
is_root() {
    [[ $EUID -eq 0 ]]
}

get_distribution() {
    if [[ -f /etc/centos-release ]]; then
        echo "CentOS"
    elif [[ -f /etc/debian_version ]]; then
        echo "Debian"
    elif [[ -f /etc/lsb-release ]] && grep -q "Ubuntu" /etc/lsb-release; then
        echo "Ubuntu"
    else
        echo "Unknown"
    fi
}

validate_port() {
    local port="$1"
    local regex='^[0-9]+$'
    
    if ! [[ "$port" =~ $regex ]]; then
        log_error "Port must be a number"
        return 1
    fi
    
    if (( port < 1 || port > 65535 )); then
        log_error "Port must be between 1 and 65535"
        return 1
    fi
    
    return 0
}

validate_secret() {
    local secret="$1"
    if ! [[ "$secret" =~ ^[0-9a-f]{32}$ ]]; then
        log_error "Secret must be 32 hexadecimal characters"
        return 1
    fi
    return 0
}

get_random_port() {
    local port
    while true; do
        port=$((RANDOM % 16383 + 49152))
        if ! command -v nc &>/dev/null || ! nc -z localhost "$port" &>/dev/null; then
            echo "$port"
            break
        fi
    done
}

get_public_ip() {
    curl -sf --connect-timeout 5 https://api.ipify.org || echo "YOUR_IP"
}

get_private_ip() {
    ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d'/' -f1 | head -1
}

check_nat() {
    local private_ip
    private_ip=$(get_private_ip)
    
    if [[ "$private_ip" =~ ^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168) ]]; then
        echo "y"
    else
        echo "n"
    fi
}

# Monitoring functions
get_service_pids() {
    local pid_count
    pid_count=$(pgrep -f "mtproto-proxy" | wc -l 2>/dev/null || echo "0")
    echo "$pid_count"
}

get_service_memory() {
    local memory_percent
    memory_percent=$(ps -C mtproto-proxy -o %mem --no-headers 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0")
    echo "${memory_percent%.*}"
}

get_service_cpu() {
    local cpu_percent
    cpu_percent=$(ps -C mtproto-proxy -o %cpu --no-headers 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0")
    echo "${cpu_percent%.*}"
}

is_service_running() {
    systemctl is-active --quiet MTProxy
}

get_restart_count() {
    local window_start
    window_start=$(date -d "1 hour ago" +%s 2>/dev/null || echo "0")
    journalctl -u MTProxy --since="@$window_start" 2>/dev/null | grep -c "Stopped\|failed\|restart" || echo "0"
}

create_monitor_script() {
    log_info "Creating monitoring script..."
    
    cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash
set -euo pipefail

# Configuration
MAX_PIDS=1000
MAX_MEMORY_PERCENT=80
MAX_CPU_PERCENT=90
CHECK_INTERVAL=300
MAX_RESTARTS=3
LOG_FILE="/var/log/mtproxy-monitor.log"

# Logging
log() {
    echo "$(date): $1" >> "$LOG_FILE"
    logger -t "mtproxy-monitor" "$1"
}

# Monitoring functions
get_service_pids() {
    pgrep -f "mtproto-proxy" | wc -l 2>/dev/null || echo "0"
}

get_service_memory() {
    ps -C mtproto-proxy -o %mem --no-headers 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0"
}

get_service_cpu() {
    ps -C mtproto-proxy -o %cpu --no-headers 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0"
}

is_service_running() {
    systemctl is-active --quiet MTProxy
}

get_restart_count() {
    local window_start
    window_start=$(date -d "1 hour ago" +%s 2>/dev/null || echo "0")
    journalctl -u MTProxy --since="@$window_start" 2>/dev/null | grep -c "Stopped\|failed\|restart" || echo "0"
}

check_resource_usage() {
    local pids memory cpu
    
    pids=$(get_service_pids)
    memory=$(get_service_memory)
    cpu=$(get_service_cpu)
    
    log "Resource Check - PIDs: $pids/$MAX_PIDS, Memory: ${memory}%/${MAX_MEMORY_PERCENT}%, CPU: ${cpu}%/${MAX_CPU_PERCENT}%"
    
    if (( pids > MAX_PIDS )) || (( memory > MAX_MEMORY_PERCENT )) || (( cpu > MAX_CPU_PERCENT )); then
        return 1
    fi
    return 0
}

safe_restart_service() {
    log "Resource limits exceeded. Attempting safe restart..."
    systemctl restart MTProxy
    sleep 15
}

emergency_reboot() {
    local reason="$1"
    log "EMERGENCY: $reason - Too many restarts, scheduling reboot"
    echo "MTProxy Monitor: Emergency reboot due to $reason" | wall
    shutdown -r +2 "MTProxy emergency reboot"
}

# Main monitor function
main_check() {
    # Check if service is running
    if ! is_service_running; then
        log "Service is not running. Starting..."
        systemctl start MTProxy
        sleep 10
        return
    fi
    
    # Check resource usage
    if ! check_resource_usage; then
        local restart_count
        restart_count=$(get_restart_count)
        
        log "High resource usage detected. Restart count: $restart_count/$MAX_RESTARTS"
        
        if (( restart_count >= MAX_RESTARTS )); then
            emergency_reboot "excessive restarts"
            return
        fi
        
        safe_restart_service
        
        # Verify restart was successful
        sleep 10
        if ! is_service_running; then
            log "Service failed to start after restart"
        fi
    fi
}

# Load custom configuration if exists
if [[ -f /etc/mtproxy/monitor.conf ]]; then
    source /etc/mtproxy/monitor.conf
fi

# Main loop
while true; do
    main_check
    sleep "$CHECK_INTERVAL"
done
EOF

    chmod +x "$MONITOR_SCRIPT"
    log_success "Monitoring script created: $MONITOR_SCRIPT"
}

create_monitor_service() {
    log_info "Creating monitoring service..."
    
    cat > "$MONITOR_SERVICE" << EOF
[Unit]
Description=MTProxy Resource Monitor
After=MTProxy.service
Wants=MTProxy.service

[Service]
Type=simple
ExecStart=$MONITOR_SCRIPT
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    log_success "Monitoring service file created: $MONITOR_SERVICE"
}

setup_monitoring() {
    if [[ "$ENABLE_MONITORING" != "y" ]]; then
        return 0
    fi
    
    log_info "Setting up resource monitoring system..."
    
    # Create monitor script
    create_monitor_script
    
    # Create monitor service
    create_monitor_service
    
    # Create configuration file
    mkdir -p /etc/mtproxy
    cat > /etc/mtproxy/monitor.conf << EOF
# MTProxy Monitor Configuration
MAX_PIDS=$MAX_PIDS
MAX_MEMORY_PERCENT=$MAX_MEMORY_PERCENT
MAX_CPU_PERCENT=$MAX_CPU_PERCENT
CHECK_INTERVAL=$CHECK_INTERVAL
MAX_RESTARTS=$MAX_RESTARTS
EOF

    # Enable and start monitoring service
    systemctl daemon-reload
    systemctl enable mtproxy-monitor
    systemctl start mtproxy-monitor
    
    if systemctl is-active --quiet mtproxy-monitor; then
        log_success "Resource monitoring service started successfully"
    else
        log_error "Failed to start monitoring service"
        systemctl status mtproxy-monitor
    fi
}

# Installation functions
install_dependencies() {
    local distro="$1"
    
    log_info "Installing dependencies for $distro..."
    
    case "$distro" in
        "CentOS")
            yum -y install epel-release
            yum -y install openssl-devel zlib-devel curl ca-certificates sed cronie vim-common git curl gcc make
            ;;
        "Ubuntu"|"Debian")
            apt-get update
            apt-get -y install git curl build-essential libssl-dev zlib1g-dev sed cron ca-certificates
            ;;
        *)
            log_error "Unsupported distribution: $distro"
            return 1
            ;;
    esac
}

install_mtproxy() {
    log_info "Installing MTProxy..."
    
    if [[ -d "$MT_PROXY_DIR" ]]; then
        log_warning "MTProxy directory already exists. Removing..."
        rm -rf "$MT_PROXY_DIR"
    fi
    
    cd /opt || exit 1
    git clone -b gcc10 https://github.com/krepver/MTProxy.git
    cd MTProxy || exit 1
    
    if ! make; then
        log_error "Failed to build MTProxy"
        exit 1
    fi
    
    log_success "MTProxy built successfully"
}

download_configs() {
    log_info "Downloading proxy configuration files..."
    
    cd "${MT_PROXY_DIR}/objs/bin" || exit 1
    
    if ! curl -sf https://core.telegram.org/getProxySecret -o proxy-secret; then
        log_error "Failed to download proxy-secret"
    else
        log_success "Proxy secret downloaded"
    fi
    
    if ! curl -sf https://core.telegram.org/getProxyConfig -o proxy-multi.conf; then
        log_error "Failed to download proxy-multi.conf"
    else
        log_success "Proxy config downloaded"
    fi
}

configure_firewall() {
    local port="$1"
    local distro="$2"
    
    log_info "Configuring firewall for port $port..."
    
    case "$distro" in
        "CentOS")
            if command -v firewall-cmd &>/dev/null; then
                firewall-cmd --zone=public --add-port="${port}/tcp" --permanent
                firewall-cmd --reload
                log_success "Firewall configured for port $port"
            else
                log_warning "firewalld not installed. Skipping firewall configuration."
            fi
            ;;
        "Ubuntu")
            if command -v ufw &>/dev/null; then
                ufw allow "${port}/tcp"
                log_success "Firewall configured for port $port"
            else
                log_warning "UFW not installed. Skipping firewall configuration."
            fi
            ;;
        "Debian")
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/iptables/rules.v4
                log_success "Firewall configured for port $port"
            fi
            ;;
    esac
}

enable_bbr() {
    local distro="$1"
    
    if [[ "$ENABLE_BBR" != "y" ]]; then
        return 0
    fi
    
    log_info "Enabling BBR congestion control..."
    
    if [[ "$distro" =~ ^(Ubuntu|Debian)$ ]]; then
        if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        fi
        if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        fi
        sysctl -p >/dev/null 2>&1
        log_success "BBR enabled"
    else
        log_warning "BBR auto-configuration not supported on $distro"
    fi
}

create_config_file() {
    log_info "Creating configuration file..."
    
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
# MTProxy Configuration
PORT=$PORT
CPU_CORES=$CPU_CORES
SECRET_ARRAY=(${SECRET_ARRAY[*]})
TAG="$TAG"
CUSTOM_ARGS="$CUSTOM_ARGS"
TLS_DOMAIN="$TLS_DOMAIN"
HAVE_NAT="$HAVE_NAT"
PUBLIC_IP="$PUBLIC_IP"
PRIVATE_IP="$PRIVATE_IP"
ENABLE_UPDATER="$ENABLE_UPDATER"
ENABLE_MONITORING="$ENABLE_MONITORING"
MAX_PIDS=$MAX_PIDS
MAX_MEMORY_PERCENT=$MAX_MEMORY_PERCENT
MAX_CPU_PERCENT=$MAX_CPU_PERCENT
CHECK_INTERVAL=$CHECK_INTERVAL
EOF
}

generate_service_file() {
    local args="-u nobody -H $PORT"
    
    for secret in "${SECRET_ARRAY[@]}"; do
        args+=" -S $secret"
    done
    
    [[ -n "$TAG" ]] && args+=" -P $TAG"
    [[ -n "$TLS_DOMAIN" ]] && args+=" -D $TLS_DOMAIN"
    [[ "$HAVE_NAT" == "y" ]] && args+=" --nat-info $PRIVATE_IP:$PUBLIC_IP"
    
    local core_count=$((CPU_CORES - 1))
    args+=" -M $core_count $CUSTOM_ARGS --aes-pwd proxy-secret proxy-multi.conf"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MTProxy
After=network.target

[Service]
Type=simple
WorkingDirectory=${MT_PROXY_DIR}/objs/bin
ExecStart=${MT_PROXY_DIR}/objs/bin/mtproto-proxy $args
Restart=on-failure
RestartSec=10
StartLimitBurst=3
StartLimitInterval=60

[Install]
WantedBy=multi-user.target
EOF
}

setup_service() {
    log_info "Setting up systemd service..."
    
    systemctl daemon-reload
    systemctl enable MTProxy
    
    if ! systemctl start MTProxy; then
        log_error "Failed to start MTProxy service"
        systemctl status MTProxy
        return 1
    fi
    
    sleep 5
    if systemctl is-active --quiet MTProxy; then
        log_success "MTProxy service started successfully"
    else
        log_error "MTProxy service failed to start"
        return 1
    fi
}

setup_updater() {
    if [[ "$ENABLE_UPDATER" != "y" ]]; then
        return 0
    fi
    
    log_info "Setting up automatic updater..."
    
    cat > "${MT_PROXY_DIR}/objs/bin/updater.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

systemctl stop MTProxy
cd /opt/MTProxy/objs/bin

if curl -sf https://core.telegram.org/getProxySecret -o proxy-secret.tmp; then
    mv proxy-secret.tmp proxy-secret
fi

if curl -sf https://core.telegram.org/getProxyConfig -o proxy-multi.conf.tmp; then
    mv proxy-multi.conf.tmp proxy-multi.conf
fi

systemctl start MTProxy
echo "Updated at $(date)" >> /var/log/mtproxy-updater.log
EOF
    
    chmod +x "${MT_PROXY_DIR}/objs/bin/updater.sh"
    
    # Add to crontab
    (crontab -l 2>/dev/null | grep -v "updater.sh"; echo "0 3 * * * ${MT_PROXY_DIR}/objs/bin/updater.sh") | crontab -
    
    log_success "Automatic updater configured"
}

generate_links() {
    log_info "Generating proxy links..."
    
    local public_ip="$PUBLIC_IP"
    if [[ "$public_ip" == "YOUR_IP" ]]; then
        public_ip=$(get_public_ip)
    fi
    
    local hex_domain=""
    if [[ -n "$TLS_DOMAIN" ]]; then
        hex_domain=$(printf "%s" "$TLS_DOMAIN" | xxd -pu | tr -d '\n' | tr '[:upper:]' '[:lower:]')
    fi
    
    echo
    echo "=== Proxy Connection Links ==="
    
    for secret in "${SECRET_ARRAY[@]}"; do
        if [[ -z "$TLS_DOMAIN" ]]; then
            echo "tg://proxy?server=${public_ip}&port=${PORT}&secret=dd${secret}"
        else
            echo "tg://proxy?server=${public_ip}&port=${PORT}&secret=ee${secret}${hex_domain}"
        fi
    done
    echo
}

# Interactive setup
interactive_setup() {
    log_info "Starting interactive MTProxy setup..."
    
    # Port selection
    while true; do
        read -rp "Enter proxy port (1-65535, -1 for random): " -e -i "443" input_port
        if [[ "$input_port" == "-1" ]]; then
            PORT=$(get_random_port)
            log_info "Selected random port: $PORT"
            break
        elif validate_port "$input_port"; then
            PORT="$input_port"
            break
        fi
    done
    
    # Secret setup
    while true; do
        echo
        echo "Secret options:"
        echo "1) Enter secret manually"
        echo "2) Generate random secret"
        read -rp "Choose option [1-2]: " -e -i "2" secret_option
        
        case "$secret_option" in
            1)
                read -rp "Enter 32-character hexadecimal secret: " secret
                if validate_secret "$secret"; then
                    SECRET_ARRAY+=("$secret")
                    break
                fi
                ;;
            2)
                secret=$(openssl rand -hex 16 2>/dev/null || hexdump -vn 16 -e '/1 "%02x"' /dev/urandom)
                SECRET_ARRAY+=("$secret")
                log_success "Generated secret: $secret"
                break
                ;;
            *)
                log_error "Invalid option"
                ;;
        esac
    done
    
    # Additional secrets
    while true; do
        if [[ ${#SECRET_ARRAY[@]} -ge 16 ]]; then
            log_warning "Maximum 16 secrets reached"
            break
        fi
        
        read -rp "Add another secret? [y/N]: " add_more
        case "$add_more" in
            [yY]*)
                secret=$(openssl rand -hex 16 2>/dev/null || hexdump -vn 16 -e '/1 "%02x"' /dev/urandom)
                SECRET_ARRAY+=("$secret")
                log_success "Generated additional secret: $secret"
                ;;
            *)
                break
                ;;
        esac
    done
    
    # TAG setup
    read -rp "Enter advertising TAG (from @MTProxybot, leave empty to skip): " TAG
    
    # CPU cores
    local available_cores=$(nproc)
    while true; do
        read -rp "Number of worker processes (1-16, recommended: $available_cores): " -e -i "$available_cores" cores
        if [[ "$cores" =~ ^[0-9]+$ ]] && (( cores >= 1 && cores <= 16 )); then
            CPU_CORES="$cores"
            break
        else
            log_error "Enter a number between 1 and 16"
        fi
    done
    
    # TLS domain
    read -rp "Enter TLS domain (for Fake-TLS, leave empty to disable): " -e -i "www.cloudflare.com" TLS_DOMAIN
    
    # NAT configuration
    HAVE_NAT=$(check_nat)
    read -rp "Is server behind NAT? [y/N]: " -e -i "$HAVE_NAT" nat_input
    HAVE_NAT="${nat_input:-$HAVE_NAT}"
    
    if [[ "$HAVE_NAT" =~ ^[yY] ]]; then
        PUBLIC_IP=$(get_public_ip)
        PRIVATE_IP=$(get_private_ip)
        read -rp "Public IP: " -e -i "$PUBLIC_IP" PUBLIC_IP
        read -rp "Private IP: " -e -i "$PRIVATE_IP" PRIVATE_IP
    fi
    
    # Monitoring configuration
    echo
    log_info "Resource Monitoring Configuration"
    read -rp "Enable automatic monitoring and recovery? [Y/n]: " monitor_input
    ENABLE_MONITORING="${monitor_input:-y}"
    
    if [[ "$ENABLE_MONITORING" =~ ^[yY] ]]; then
        read -rp "Maximum PIDs allowed [1000]: " max_pids
        MAX_PIDS="${max_pids:-1000}"
        
        read -rp "Maximum memory usage % [80]: " max_mem
        MAX_MEMORY_PERCENT="${max_mem:-80}"
        
        read -rp "Maximum CPU usage % [90]: " max_cpu
        MAX_CPU_PERCENT="${max_cpu:-90}"
        
        read -rp "Check interval in seconds [300]: " interval
        CHECK_INTERVAL="${interval:-300}"
    fi
    
    # Custom arguments
    read -rp "Enter custom arguments (leave empty if unsure): " CUSTOM_ARGS
    
    # Final confirmation
    echo
    log_warning "About to install MTProxy with the following configuration:"
    echo "Port: $PORT"
    echo "Secrets: ${#SECRET_ARRAY[@]} configured"
    echo "Workers: $CPU_CORES"
    echo "TLS Domain: ${TLS_DOMAIN:-Disabled}"
    echo "NAT: $HAVE_NAT"
    echo "Monitoring: $ENABLE_MONITORING"
    if [[ "$ENABLE_MONITORING" == "y" ]]; then
        echo "Max PIDs: $MAX_PIDS"
        echo "Max Memory: $MAX_MEMORY_PERCENT%"
        echo "Max CPU: $MAX_CPU_PERCENT%"
    fi
    echo
    read -rp "Continue with installation? [Y/n]: " confirm
    [[ "$confirm" =~ ^[nN] ]] && exit 0
}

# Main installation function
main_installation() {
    local distro=$(get_distribution)
    
    if [[ "$distro" == "Unknown" ]]; then
        log_error "Unsupported Linux distribution"
        exit 1
    fi
    
    if ! is_root; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Interactive setup if not auto-install
    if ! $AUTO_INSTALL; then
        interactive_setup
    fi
    
    # Set default values if not set
    : "${PUBLIC_IP:=$(get_public_ip)}"
    : "${PRIVATE_IP:=$(get_private_ip)}"
    : "${CPU_CORES:=$(nproc)}"
    : "${HAVE_NAT:=$(check_nat)}"
    
    # Install dependencies
    install_dependencies "$distro"
    
    # Install MTProxy
    install_mtproxy
    
    # Download configurations
    download_configs
    
    # Create config file
    create_config_file
    
    # Generate service file
    generate_service_file
    
    # Configure firewall
    configure_firewall "$PORT" "$distro"
    
    # Enable BBR
    enable_bbr "$distro"
    
    # Setup service
    setup_service
    
    # Setup updater
    setup_updater
    
    # Setup monitoring
    setup_monitoring
    
    # Generate links
    generate_links
    
    log_success "MTProxy installation completed successfully!"
    log_info "Configuration file: $CONFIG_FILE"
    log_info "Service control: systemctl {start|stop|status} MTProxy"
    if [[ "$ENABLE_MONITORING" == "y" ]]; then
        log_info "Monitor service: systemctl {start|stop|status} mtproxy-monitor"
        log_info "Monitor log: $MONITOR_LOG"
    fi
}

# Management functions
show_links() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "MTProxy not installed"
        exit 1
    fi
    
    source "$CONFIG_FILE" 2>/dev/null || {
        log_error "Failed to load configuration"
        exit 1
    }
    generate_links
}

show_status() {
    log_info "MTProxy Service Status:"
    systemctl status MTProxy --no-pager -l
    
    if [[ -f "$MONITOR_SERVICE" ]]; then
        echo
        log_info "Monitor Service Status:"
        systemctl status mtproxy-monitor --no-pager -l
        
        echo
        log_info "Recent Monitor Log:"
        tail -20 "$MONITOR_LOG" 2>/dev/null || echo "No monitor log found"
    fi
    
    echo
    log_info "Resource Usage:"
    echo "PIDs: $(get_service_pids)/${MAX_PIDS}"
    echo "Memory: $(get_service_memory)%/${MAX_MEMORY_PERCENT}%"
    echo "CPU: $(get_service_cpu)%/${MAX_CPU_PERCENT}%"
}

uninstall_proxy() {
    log_warning "This will completely remove MTProxy and all its components"
    read -rp "Are you sure? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY] ]] && exit 0
    
    # Stop services
    systemctl stop MTProxy 2>/dev/null || true
    systemctl stop mtproxy-monitor 2>/dev/null || true
    
    # Disable services
    systemctl disable MTProxy 2>/dev/null || true
    systemctl disable mtproxy-monitor 2>/dev/null || true
    
    # Remove service files
    rm -f "$SERVICE_FILE"
    rm -f "$MONITOR_SERVICE"
    systemctl daemon-reload
    
    # Remove firewall rules
    local distro=$(get_distribution)
    local port=$(source "$CONFIG_FILE" 2>/dev/null && echo "$PORT" || echo "443")
    
    case "$distro" in
        "CentOS") 
            firewall-cmd --remove-port="${port}/tcp" --permanent 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
            ;;
        "Ubuntu") 
            ufw delete allow "${port}/tcp" 2>/dev/null || true
            ;;
        "Debian") 
            iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            ;;
    esac
    
    # Remove files
    rm -rf "$MT_PROXY_DIR"
    rm -f "$MONITOR_SCRIPT"
    rm -rf /etc/mtproxy
    rm -f "$MONITOR_LOG"
    rm -f /var/log/mtproxy-updater.log
    
    # Remove crontab entries
    crontab -l 2>/dev/null | grep -v "mtproxy\|updater.sh" | crontab -
    
    log_success "MTProxy completely uninstalled"
}

show_usage() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

Usage: $0 [options]

Options:
  -h, --help            Show this help message
  -p, --port PORT       Set proxy port
  -s, --secret SECRET   Add a secret (can be used multiple times)
  -t, --tag TAG         Set advertising tag
  --workers N           Number of worker processes
  --tls-domain DOMAIN   Set TLS domain for Fake-TLS
  --no-updater          Disable automatic updates
  --no-bbr              Disable BBR congestion control
  --enable-monitoring   Enable resource monitoring
  --disable-monitoring  Disable resource monitoring
  --max-pids NUM        Set maximum PIDs for monitoring
  --check-interval SEC  Set monitoring check interval

Management commands:
  show-links            Show proxy connection links
  show-status           Show service status and resource usage
  uninstall             Uninstall MTProxy completely

Examples:
  $0                    # Interactive installation
  $0 --port 443 --secret abc123... --workers 4 --enable-monitoring
  $0 show-links         # Show connection links
  $0 show-status        # Show current status
  $0 uninstall          # Uninstall MTProxy
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            show-links)
                show_links
                exit 0
                ;;
            show-status)
                show_status
                exit 0
                ;;
            uninstall)
                uninstall_proxy
                exit 0
                ;;
            -p|--port)
                validate_port "$2" || exit 1
                PORT="$2"
                AUTO_INSTALL=true
                shift 2
                ;;
            -s|--secret)
                validate_secret "$2" || exit 1
                SECRET_ARRAY+=("$2")
                AUTO_INSTALL=true
                shift 2
                ;;
            -t|--tag)
                TAG="$2"
                AUTO_INSTALL=true
                shift 2
                ;;
            --workers)
                if [[ "$2" =~ ^[0-9]+$ ]] && (( "$2" >= 1 && "$2" <= 16 )); then
                    CPU_CORES="$2"
                else
                    log_error "Workers must be between 1 and 16"
                    exit 1
                fi
                AUTO_INSTALL=true
                shift 2
                ;;
            --tls-domain)
                TLS_DOMAIN="$2"
                AUTO_INSTALL=true
                shift 2
                ;;
            --no-updater)
                ENABLE_UPDATER="n"
                AUTO_INSTALL=true
                shift
                ;;
            --no-bbr)
                ENABLE_BBR="n"
                AUTO_INSTALL=true
                shift
                ;;
            --enable-monitoring)
                ENABLE_MONITORING="y"
                AUTO_INSTALL=true
                shift
                ;;
            --disable-monitoring)
                ENABLE_MONITORING="n"
                AUTO_INSTALL=true
                shift
                ;;
            --max-pids)
                if [[ "$2" =~ ^[0-9]+$ ]] && (( "$2" >= 100 )); then
                    MAX_PIDS="$2"
                else
                    log_error "Max PIDs must be at least 100"
                    exit 1
                fi
                AUTO_INSTALL=true
                shift 2
                ;;
            --check-interval)
                if [[ "$2" =~ ^[0-9]+$ ]] && (( "$2" >= 60 )); then
                    CHECK_INTERVAL="$2"
                else
                    log_error "Check interval must be at least 60 seconds"
                    exit 1
                fi
                AUTO_INSTALL=true
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    parse_arguments "$@"
    
    if [[ -d "$MT_PROXY_DIR" ]] && ! $AUTO_INSTALL; then
        log_info "MTProxy is already installed"
        echo "1) Show connection links"
        echo "2) Show status"
        echo "3) Uninstall"
        echo "4) Exit"
        read -rp "Choose option [1-4]: " option
        
        case "$option" in
            1) show_links ;;
            2) show_status ;;
            3) uninstall_proxy ;;
            *) exit 0 ;;
        esac
    else
        main_installation
    fi
}

# Run main function with all arguments
main "$@"
