#!/bin/zsh
#
# Sub2API macOS Installation Script
# Sub2API macOS 安装脚本
# Usage: curl -sSL https://raw.githubusercontent.com/liafonx/sub2api/main/deploy/install-macos.sh | sudo zsh
#
# Known limitations vs Linux version:
#   - No equivalent of systemd's NoNewPrivileges/ProtectSystem/ProtectHome/PrivateTmp
#   - No automatic log rotation (logs grow unbounded; configure newsyslog manually if needed)
#   - Additional app environment variables (DB config, etc.) must be added to the plist's
#     EnvironmentVariables dict — launchd does not inherit the shell environment
#   - /opt/sub2api is non-standard on macOS but kept for consistency with the Linux install
#

set -e

# Fix $0 when script is piped: curl ... | sudo zsh
SCRIPT_NAME="${0:t}"
[[ "$SCRIPT_NAME" = "zsh" || "$SCRIPT_NAME" = "bash" ]] && SCRIPT_NAME="install-macos.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="Wei-Shaw/sub2api"
INSTALL_DIR="/opt/sub2api"
SERVICE_NAME="sub2api"
SERVICE_USER="sub2api"
CONFIG_DIR="/etc/sub2api"

# macOS-specific
LAUNCHD_PLIST="/Library/LaunchDaemons/com.sub2api.plist"
LAUNCHD_LABEL="com.sub2api"
LOG_DIR="/var/log/sub2api"

# Server configuration (will be set by user)
SERVER_HOST="0.0.0.0"
SERVER_PORT="8080"

# Language (default: zh = Chinese)
LANG_CHOICE="zh"

# Temp dir (set in download_and_extract, cleaned up via global trap in main)
TEMP_DIR=""

# ============================================================
# Language strings / 语言字符串
# ============================================================

# Chinese strings
typeset -A MSG_ZH=(
    # General
    ["info"]="信息"
    ["success"]="成功"
    ["warning"]="警告"
    ["error"]="错误"

    # Language selection
    ["select_lang"]="请选择语言 / Select language"
    ["lang_zh"]="中文"
    ["lang_en"]="English"
    ["enter_choice"]="请输入选择 (默认: 1)"

    # Installation
    ["install_title"]="Sub2API macOS 安装脚本"
    ["run_as_root"]="请使用 root 权限运行 (使用 sudo)"
    ["detected_platform"]="检测到平台"
    ["unsupported_arch"]="不支持的架构"
    ["unsupported_os"]="不支持的操作系统"
    ["missing_deps"]="缺少依赖"
    ["install_deps_first"]="请先安装以下依赖"
    ["fetching_version"]="正在获取最新版本..."
    ["latest_version"]="最新版本"
    ["failed_get_version"]="获取最新版本失败"
    ["downloading"]="正在下载"
    ["download_failed"]="下载失败"
    ["verifying_checksum"]="正在校验文件..."
    ["checksum_verified"]="校验通过"
    ["checksum_failed"]="校验失败"
    ["checksum_not_found"]="无法验证校验和（checksums.txt 未找到）"
    ["extracting"]="正在解压..."
    ["binary_installed"]="二进制文件已安装到"
    ["user_exists"]="用户已存在"
    ["creating_user"]="正在创建系统用户"
    ["user_created"]="用户已创建"
    ["setting_up_dirs"]="正在设置目录..."
    ["dirs_configured"]="目录配置完成"
    ["installing_service"]="正在安装 launchd 服务..."
    ["service_installed"]="launchd 服务已安装"
    ["ready_for_setup"]="准备就绪，可以启动设置向导"

    # Completion
    ["install_complete"]="Sub2API 安装完成！"
    ["install_dir"]="安装目录"
    ["next_steps"]="后续步骤"
    ["step1_check_services"]="确保 PostgreSQL 和 Redis 正在运行："
    ["step2_start_service"]="启动 Sub2API 服务："
    ["step4_open_wizard"]="在浏览器中打开设置向导："
    ["wizard_guide"]="设置向导将引导您完成："
    ["wizard_db"]="数据库配置"
    ["wizard_redis"]="Redis 配置"
    ["wizard_admin"]="管理员账号创建"
    ["useful_commands"]="常用命令"
    ["cmd_status"]="查看状态"
    ["cmd_logs"]="查看日志"
    ["cmd_restart"]="重启服务"
    ["cmd_stop"]="停止服务"

    # Upgrade
    ["upgrading"]="正在升级 Sub2API..."
    ["current_version"]="当前版本"
    ["stopping_service"]="正在停止服务..."
    ["backup_created"]="备份已创建"
    ["starting_service"]="正在启动服务..."
    ["upgrade_complete"]="升级完成！"

    # Version install
    ["installing_version"]="正在安装指定版本"
    ["version_not_found"]="指定版本不存在"
    ["same_version"]="已经是该版本，无需操作"
    ["rollback_complete"]="版本回退完成！"
    ["install_version_complete"]="指定版本安装完成！"
    ["validating_version"]="正在验证版本..."
    ["available_versions"]="可用版本列表"
    ["fetching_versions"]="正在获取可用版本..."
    ["not_installed"]="Sub2API 尚未安装，请先执行全新安装"
    ["fresh_install_hint"]="用法"

    # Uninstall
    ["uninstall_confirm"]="这将从系统中移除 Sub2API。"
    ["are_you_sure"]="确定要继续吗？(y/N)"
    ["uninstall_cancelled"]="卸载已取消"
    ["removing_files"]="正在移除文件..."
    ["removing_install_dir"]="正在移除安装目录..."
    ["removing_user"]="正在移除用户..."
    ["config_not_removed"]="配置目录未被移除"
    ["remove_manually"]="如不再需要，请手动删除"
    ["removing_install_lock"]="正在移除安装锁文件..."
    ["install_lock_removed"]="安装锁文件已移除，重新安装时将进入设置向导"
    ["purge_prompt"]="是否同时删除配置目录？这将清除所有配置和数据 [y/N]: "
    ["removing_config_dir"]="正在移除配置目录..."
    ["uninstall_complete"]="Sub2API 已卸载"

    # Help
    ["usage"]="用法"
    ["cmd_none"]="(无参数)"
    ["cmd_install"]="安装 Sub2API"
    ["cmd_upgrade"]="升级到最新版本"
    ["cmd_uninstall"]="卸载 Sub2API"
    ["cmd_install_version"]="安装/回退到指定版本"
    ["cmd_list_versions"]="列出可用版本"
    ["opt_version"]="指定要安装的版本号 (例如: v1.0.0)"

    # Server configuration
    ["server_config_title"]="服务器配置"
    ["server_config_desc"]="配置 Sub2API 服务监听地址"
    ["server_host_prompt"]="服务器监听地址"
    ["server_host_hint"]="0.0.0.0 表示监听所有网卡，127.0.0.1 仅本地访问"
    ["server_port_prompt"]="服务器端口"
    ["server_port_hint"]="建议使用 1024-65535 之间的端口"
    ["server_config_summary"]="服务器配置"
    ["invalid_port"]="无效端口号，请输入 1-65535 之间的数字"

    # Service management
    ["service_started"]="服务已启动"
    ["service_start_failed"]="服务启动失败，请检查日志"
    ["enabling_autostart"]="正在设置开机自启（launchd RunAtLoad）..."
    ["autostart_enabled"]="开机自启已通过 launchd RunAtLoad 启用"
    ["getting_public_ip"]="正在获取公网 IP..."
    ["public_ip_failed"]="无法获取公网 IP，使用本地 IP"
)

# English strings
typeset -A MSG_EN=(
    # General
    ["info"]="INFO"
    ["success"]="SUCCESS"
    ["warning"]="WARNING"
    ["error"]="ERROR"

    # Language selection
    ["select_lang"]="请选择语言 / Select language"
    ["lang_zh"]="中文"
    ["lang_en"]="English"
    ["enter_choice"]="Enter your choice (default: 1)"

    # Installation
    ["install_title"]="Sub2API macOS Installation Script"
    ["run_as_root"]="Please run as root (use sudo)"
    ["detected_platform"]="Detected platform"
    ["unsupported_arch"]="Unsupported architecture"
    ["unsupported_os"]="Unsupported OS"
    ["missing_deps"]="Missing dependencies"
    ["install_deps_first"]="Please install them first"
    ["fetching_version"]="Fetching latest version..."
    ["latest_version"]="Latest version"
    ["failed_get_version"]="Failed to get latest version"
    ["downloading"]="Downloading"
    ["download_failed"]="Download failed"
    ["verifying_checksum"]="Verifying checksum..."
    ["checksum_verified"]="Checksum verified"
    ["checksum_failed"]="Checksum verification failed"
    ["checksum_not_found"]="Could not verify checksum (checksums.txt not found)"
    ["extracting"]="Extracting..."
    ["binary_installed"]="Binary installed to"
    ["user_exists"]="User already exists"
    ["creating_user"]="Creating system user"
    ["user_created"]="User created"
    ["setting_up_dirs"]="Setting up directories..."
    ["dirs_configured"]="Directories configured"
    ["installing_service"]="Installing launchd service..."
    ["service_installed"]="launchd plist installed"
    ["ready_for_setup"]="Ready for Setup Wizard"

    # Completion
    ["install_complete"]="Sub2API installation completed!"
    ["install_dir"]="Installation directory"
    ["next_steps"]="NEXT STEPS"
    ["step1_check_services"]="Make sure PostgreSQL and Redis are running:"
    ["step2_start_service"]="Start Sub2API service:"
    ["step4_open_wizard"]="Open the Setup Wizard in your browser:"
    ["wizard_guide"]="The Setup Wizard will guide you through:"
    ["wizard_db"]="Database configuration"
    ["wizard_redis"]="Redis configuration"
    ["wizard_admin"]="Admin account creation"
    ["useful_commands"]="USEFUL COMMANDS"
    ["cmd_status"]="Check status"
    ["cmd_logs"]="View logs"
    ["cmd_restart"]="Restart"
    ["cmd_stop"]="Stop"

    # Upgrade
    ["upgrading"]="Upgrading Sub2API..."
    ["current_version"]="Current version"
    ["stopping_service"]="Stopping service..."
    ["backup_created"]="Backup created"
    ["starting_service"]="Starting service..."
    ["upgrade_complete"]="Upgrade completed!"

    # Version install
    ["installing_version"]="Installing specified version"
    ["version_not_found"]="Specified version not found"
    ["same_version"]="Already at this version, no action needed"
    ["rollback_complete"]="Version rollback completed!"
    ["install_version_complete"]="Specified version installed!"
    ["validating_version"]="Validating version..."
    ["available_versions"]="Available versions"
    ["fetching_versions"]="Fetching available versions..."
    ["not_installed"]="Sub2API is not installed. Please run a fresh install first"
    ["fresh_install_hint"]="Usage"

    # Uninstall
    ["uninstall_confirm"]="This will remove Sub2API from your system."
    ["are_you_sure"]="Are you sure? (y/N)"
    ["uninstall_cancelled"]="Uninstall cancelled"
    ["removing_files"]="Removing files..."
    ["removing_install_dir"]="Removing installation directory..."
    ["removing_user"]="Removing user..."
    ["config_not_removed"]="Config directory was NOT removed."
    ["remove_manually"]="Remove it manually if you no longer need it."
    ["removing_install_lock"]="Removing install lock file..."
    ["install_lock_removed"]="Install lock removed. Setup wizard will appear on next install."
    ["purge_prompt"]="Also remove config directory? This will delete all config and data [y/N]: "
    ["removing_config_dir"]="Removing config directory..."
    ["uninstall_complete"]="Sub2API has been uninstalled"

    # Help
    ["usage"]="Usage"
    ["cmd_none"]="(none)"
    ["cmd_install"]="Install Sub2API"
    ["cmd_upgrade"]="Upgrade to the latest version"
    ["cmd_uninstall"]="Remove Sub2API"
    ["cmd_install_version"]="Install/rollback to a specific version"
    ["cmd_list_versions"]="List available versions"
    ["opt_version"]="Specify version to install (e.g., v1.0.0)"

    # Server configuration
    ["server_config_title"]="Server Configuration"
    ["server_config_desc"]="Configure Sub2API server listen address"
    ["server_host_prompt"]="Server listen address"
    ["server_host_hint"]="0.0.0.0 listens on all interfaces, 127.0.0.1 for local only"
    ["server_port_prompt"]="Server port"
    ["server_port_hint"]="Recommended range: 1024-65535"
    ["server_config_summary"]="Server configuration"
    ["invalid_port"]="Invalid port number, please enter a number between 1-65535"

    # Service management
    ["service_started"]="Service started"
    ["service_start_failed"]="Service failed to start, please check logs"
    ["enabling_autostart"]="Enabling auto-start via launchd RunAtLoad..."
    ["autostart_enabled"]="Auto-start enabled via launchd RunAtLoad"
    ["getting_public_ip"]="Getting public IP..."
    ["public_ip_failed"]="Failed to get public IP, using local IP"
)

# Get message based on current language
msg() {
    local key="$1"
    if [ "$LANG_CHOICE" = "en" ]; then
        echo "${MSG_EN[$key]}"
    else
        echo "${MSG_ZH[$key]}"
    fi
}

# Print functions
print_info() {
    echo -e "${BLUE}[$(msg 'info')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[$(msg 'success')]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[$(msg 'warning')]${NC} $1"
}

print_error() {
    echo -e "${RED}[$(msg 'error')]${NC} $1"
}

# Check if running interactively (can access terminal)
# When piped (curl | zsh), stdin is not a terminal, but /dev/tty may still be available.
# Permission check alone is insufficient — verify the device is actually functional.
is_interactive() {
    [ -e /dev/tty ] && [ -r /dev/tty ] && [ -w /dev/tty ] && \
        ( exec 3<>/dev/tty ) 2>/dev/null
}

# Select language
select_language() {
    if ! is_interactive; then
        LANG_CHOICE="zh"
        return
    fi

    echo ""
    echo -e "${CYAN}=============================================="
    echo "  $(msg 'select_lang')"
    echo "==============================================${NC}"
    echo ""
    echo "  1) $(msg 'lang_zh') (默认/default)"
    echo "  2) $(msg 'lang_en')"
    echo ""

    print -n "$(msg 'enter_choice'): "
    read lang_input < /dev/tty

    case "$lang_input" in
        2|en|EN|english|English)
            LANG_CHOICE="en"
            ;;
        *)
            LANG_CHOICE="zh"
            ;;
    esac

    echo ""
}

# Validate port number
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

# Configure server settings
configure_server() {
    if ! is_interactive; then
        print_info "$(msg 'server_config_summary'): ${SERVER_HOST}:${SERVER_PORT} (default)"
        return
    fi

    echo ""
    echo -e "${CYAN}=============================================="
    echo "  $(msg 'server_config_title')"
    echo "==============================================${NC}"
    echo ""
    echo -e "${BLUE}$(msg 'server_config_desc')${NC}"
    echo ""

    # Server host
    echo -e "${YELLOW}$(msg 'server_host_hint')${NC}"
    print -n "$(msg 'server_host_prompt') [${SERVER_HOST}]: "
    read input_host < /dev/tty
    if [ -n "$input_host" ]; then
        SERVER_HOST="$input_host"
    fi

    echo ""

    # Server port
    echo -e "${YELLOW}$(msg 'server_port_hint')${NC}"
    while true; do
        print -n "$(msg 'server_port_prompt') [${SERVER_PORT}]: "
        read input_port < /dev/tty
        if [ -z "$input_port" ]; then
            break
        elif validate_port "$input_port"; then
            SERVER_PORT="$input_port"
            break
        else
            print_error "$(msg 'invalid_port')"
        fi
    done

    echo ""
    print_info "$(msg 'server_config_summary'): ${SERVER_HOST}:${SERVER_PORT}"
    echo ""
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "$(msg 'run_as_root')"
        exit 1
    fi
}

# Detect OS and architecture (macOS only)
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            print_error "$(msg 'unsupported_arch'): $ARCH"
            exit 1
            ;;
    esac

    case "$OS" in
        darwin)
            OS="darwin"
            ;;
        *)
            print_error "This script is for macOS only. For Linux, use install.sh"
            exit 1
            ;;
    esac

    print_info "$(msg 'detected_platform'): ${OS}_${ARCH}"
}

# Check dependencies
check_dependencies() {
    local missing=()

    if ! command -v curl &>/dev/null; then
        missing+=("curl")
    fi

    if ! command -v shasum &>/dev/null; then
        missing+=("shasum")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        print_error "$(msg 'missing_deps'): ${missing[*]}"
        print_info "$(msg 'install_deps_first')"
        exit 1
    fi
}

# Get latest release version
get_latest_version() {
    print_info "$(msg 'fetching_version')"
    LATEST_VERSION=$(curl -s --connect-timeout 10 --max-time 30 "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$LATEST_VERSION" ]; then
        print_error "$(msg 'failed_get_version')"
        print_info "Please check your network connection or try again later."
        exit 1
    fi

    print_info "$(msg 'latest_version'): $LATEST_VERSION"
}

# List available versions
list_versions() {
    print_info "$(msg 'fetching_versions')"

    local versions
    versions=$(curl -s --connect-timeout 10 --max-time 30 "https://api.github.com/repos/${GITHUB_REPO}/releases" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | head -20)

    if [ -z "$versions" ]; then
        print_error "$(msg 'failed_get_version')"
        print_info "Please check your network connection or try again later."
        exit 1
    fi

    echo ""
    echo "$(msg 'available_versions'):"
    echo "----------------------------------------"
    echo "$versions" | while read -r version; do
        echo "  $version"
    done
    echo "----------------------------------------"
    echo ""
}

# Validate if a version exists
validate_version() {
    local version="$1"

    if [ -z "$version" ]; then
        print_error "$(msg 'opt_version')" >&2
        exit 1
    fi

    if [[ ! "$version" =~ ^v ]]; then
        version="v$version"
    fi

    print_info "$(msg 'validating_version') $version" >&2

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 30 "https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${version}" 2>/dev/null)

    if [ -z "$http_code" ] || ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
        print_error "Network error: Failed to connect to GitHub API" >&2
        exit 1
    fi

    if [ "$http_code" != "200" ]; then
        print_error "$(msg 'version_not_found'): $version" >&2
        echo "" >&2
        list_versions >&2
        exit 1
    fi

    echo "$version"
}

# Get current installed version
get_current_version() {
    if [ -f "$INSTALL_DIR/sub2api" ]; then
        "$INSTALL_DIR/sub2api" --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown"
    else
        echo "not_installed"
    fi
}

# Download and extract
download_and_extract() {
    local version_num=${LATEST_VERSION#v}
    local archive_name="sub2api_${version_num}_${OS}_${ARCH}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/${archive_name}"
    local checksum_url="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/checksums.txt"

    print_info "$(msg 'downloading') ${archive_name}..."

    # Create temp directory (global TEMP_DIR cleaned up by trap in main)
    TEMP_DIR=$(mktemp -d)

    # Download archive
    if ! curl -sL "$download_url" -o "$TEMP_DIR/$archive_name"; then
        print_error "$(msg 'download_failed')"
        exit 1
    fi

    # Download and verify checksum
    print_info "$(msg 'verifying_checksum')"
    if curl -sL "$checksum_url" -o "$TEMP_DIR/checksums.txt" 2>/dev/null; then
        local expected_checksum=$(grep "$archive_name" "$TEMP_DIR/checksums.txt" | awk '{print $1}')
        local actual_checksum=$(shasum -a 256 "$TEMP_DIR/$archive_name" | awk '{print $1}')

        if [ "$expected_checksum" != "$actual_checksum" ]; then
            print_error "$(msg 'checksum_failed')"
            print_error "Expected: $expected_checksum"
            print_error "Actual: $actual_checksum"
            exit 1
        fi
        print_success "$(msg 'checksum_verified')"
    else
        print_warning "$(msg 'checksum_not_found')"
    fi

    # Extract
    print_info "$(msg 'extracting')"
    tar -xzf "$TEMP_DIR/$archive_name" -C "$TEMP_DIR"

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Copy binary
    cp "$TEMP_DIR/sub2api" "$INSTALL_DIR/sub2api"
    chmod +x "$INSTALL_DIR/sub2api"

    # Remove macOS quarantine attribute so Gatekeeper doesn't block execution
    xattr -d com.apple.quarantine "$INSTALL_DIR/sub2api" 2>/dev/null || true

    # Copy deploy files if they exist in the archive
    # Use cp -R with trailing /. to avoid zsh nomatch error on glob expansion
    if [ -d "$TEMP_DIR/deploy" ]; then
        cp -R "$TEMP_DIR/deploy/." "$INSTALL_DIR/" 2>/dev/null || true
    fi

    print_success "$(msg 'binary_installed') $INSTALL_DIR/sub2api"
}

# Create system user (macOS dscl)
create_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        print_info "$(msg 'user_exists'): $SERVICE_USER"
        # Fix shell if it was set to /bin/false or /sbin/nologin
        local current_shell
        current_shell=$(dscl . -read "/Users/$SERVICE_USER" UserShell 2>/dev/null | awk '{print $2}')
        if [ "$current_shell" = "/bin/false" ] || [ "$current_shell" = "/sbin/nologin" ]; then
            print_info "Fixing user shell for launchd compatibility..."
            if dscl . -change "/Users/$SERVICE_USER" UserShell "$current_shell" /bin/sh 2>/dev/null; then
                print_success "User shell updated to /bin/sh"
            else
                print_warning "Failed to update user shell."
                print_warning "Manual fix: sudo dscl . -change /Users/$SERVICE_USER UserShell $current_shell /bin/sh"
            fi
        fi
    else
        print_info "$(msg 'creating_user') $SERVICE_USER..."

        # Find a free GID >= 501 (avoid Apple's reserved 0-500 range; cap at 60000)
        local gid=501
        while dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -q "^${gid}$"; do
            gid=$((gid + 1))
            [ "$gid" -gt 60000 ] && { print_error "Could not find free GID"; exit 1; }
        done

        # Create dedicated group
        dscl . -create "/Groups/$SERVICE_USER"
        dscl . -create "/Groups/$SERVICE_USER" RealName "Sub2API Service Group"
        dscl . -create "/Groups/$SERVICE_USER" PrimaryGroupID "$gid"

        # Find a free UID >= 501 (avoid Apple's reserved 0-500 range; cap at 60000)
        local uid=501
        while dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | grep -q "^${uid}$"; do
            uid=$((uid + 1))
            [ "$uid" -gt 60000 ] && { print_error "Could not find free UID"; exit 1; }
        done

        # Create service user with dedicated GID
        dscl . -create "/Users/$SERVICE_USER"
        dscl . -create "/Users/$SERVICE_USER" UserShell /bin/sh
        dscl . -create "/Users/$SERVICE_USER" RealName "Sub2API Service User"
        dscl . -create "/Users/$SERVICE_USER" UniqueID "$uid"
        dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$gid"
        dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory "$INSTALL_DIR"
        dscl . -create "/Users/$SERVICE_USER" IsHidden 1
        dscl . -append "/Groups/$SERVICE_USER" GroupMembership "$SERVICE_USER"

        # Hide from login window (UIDs >= 501 are shown by default without this)
        defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList \
            -array-add "$SERVICE_USER" 2>/dev/null || true

        dscacheutil -flushcache 2>/dev/null || true
        print_success "$(msg 'user_created')"
    fi
}

# Setup directories and permissions
setup_directories() {
    print_info "$(msg 'setting_up_dirs')"

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/data"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"

    # Use user-only chown: dscl group may not be immediately resolvable by name
    chown -R "$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER" "$CONFIG_DIR"
    chown -R "$SERVICE_USER" "$LOG_DIR"
    chmod 750 "$LOG_DIR"

    print_success "$(msg 'dirs_configured')"
}

# Install launchd service (replaces systemd unit)
install_service() {
    print_info "$(msg 'installing_service')"

    # Write launchd plist with variable expansion (unquoted heredoc)
    cat > "$LAUNCHD_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/sub2api</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>UserName</key>
    <string>${SERVICE_USER}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/stderr.log</string>
    <key>Umask</key>
    <integer>23</integer>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GIN_MODE</key>
        <string>release</string>
    </dict>
</dict>
</plist>
EOF

    # launchd requires plist owned by root:wheel with mode 644
    chmod 644 "$LAUNCHD_PLIST"
    chown root:wheel "$LAUNCHD_PLIST"

    # Validate plist syntax before attempting to load
    if ! plutil -lint "$LAUNCHD_PLIST" 2>/dev/null; then
        print_error "Plist validation failed — aborting service install"
        rm -f "$LAUNCHD_PLIST"
        exit 1
    fi

    print_success "$(msg 'service_installed')"
}

# Prepare for setup wizard
prepare_for_setup() {
    print_success "$(msg 'ready_for_setup')"
}

# Get public IP address
get_public_ip() {
    print_info "$(msg 'getting_public_ip')"

    local response
    response=$(curl -s --connect-timeout 5 --max-time 10 "https://ipinfo.io/json" 2>/dev/null)

    if [ -n "$response" ]; then
        PUBLIC_IP=$(echo "$response" | grep -o '"ip": *"[^"]*"' | sed 's/"ip": *"\([^"]*\)"/\1/')
        if [ -n "$PUBLIC_IP" ]; then
            print_success "Public IP: $PUBLIC_IP"
            return 0
        fi
    fi

    print_warning "$(msg 'public_ip_failed')"
    # macOS does not have hostname -I; use ipconfig / ifconfig fallback
    PUBLIC_IP=$(ipconfig getifaddr en0 2>/dev/null \
        || ipconfig getifaddr en1 2>/dev/null \
        || ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' \
        || echo "YOUR_SERVER_IP")
    return 1
}

# Start service (launchd)
start_service() {
    print_info "$(msg 'starting_service')"

    # Unload/bootout in case a previous instance is loaded
    launchctl bootout system/"$LAUNCHD_LABEL" 2>/dev/null || \
        launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true

    # Use modern bootstrap API, fall back to deprecated load for older macOS
    if launchctl bootstrap system/ "$LAUNCHD_PLIST" 2>/dev/null || \
       launchctl load "$LAUNCHD_PLIST" 2>/dev/null; then
        print_success "$(msg 'service_started')"
        return 0
    else
        print_error "$(msg 'service_start_failed')"
        print_info "tail -f ${LOG_DIR}/stderr.log"
        return 1
    fi
}

# Enable service auto-start
# On macOS, RunAtLoad=true in the plist already handles this — this is a no-op stub.
enable_autostart() {
    print_info "$(msg 'enabling_autostart')"
    # RunAtLoad=true in the plist persists the service across reboots automatically.
    print_success "$(msg 'autostart_enabled')"
    return 0
}

# Print completion message
print_completion() {
    local display_host="${PUBLIC_IP:-YOUR_SERVER_IP}"
    if [ "$SERVER_HOST" = "127.0.0.1" ]; then
        display_host="127.0.0.1"
    fi

    echo ""
    echo "=============================================="
    print_success "$(msg 'install_complete')"
    echo "=============================================="
    echo ""
    echo "$(msg 'install_dir'): $INSTALL_DIR"
    echo "$(msg 'server_config_summary'): ${SERVER_HOST}:${SERVER_PORT}"
    echo ""
    echo "=============================================="
    echo "  $(msg 'step4_open_wizard')"
    echo "=============================================="
    echo ""
    print_info "     http://${display_host}:${SERVER_PORT}"
    echo ""
    echo "     $(msg 'wizard_guide')"
    echo "     - $(msg 'wizard_db')"
    echo "     - $(msg 'wizard_redis')"
    echo "     - $(msg 'wizard_admin')"
    echo ""
    echo "=============================================="
    echo "  $(msg 'useful_commands')"
    echo "=============================================="
    echo ""
    echo "  $(msg 'cmd_status'):   sudo launchctl print system/${LAUNCHD_LABEL}"
    echo "  $(msg 'cmd_logs'):     tail -f ${LOG_DIR}/stdout.log"
    echo "  $(msg 'cmd_restart'):  sudo launchctl bootout system/${LAUNCHD_LABEL} && sudo launchctl bootstrap system/ ${LAUNCHD_PLIST}"
    echo "  $(msg 'cmd_stop'):     sudo launchctl bootout system/${LAUNCHD_LABEL}"
    echo ""
    echo "=============================================="
}

# Upgrade function
upgrade() {
    if [ ! -f "$INSTALL_DIR/sub2api" ]; then
        print_error "$(msg 'not_installed')"
        print_info "$(msg 'fresh_install_hint'): $SCRIPT_NAME install"
        exit 1
    fi

    print_info "$(msg 'upgrading')"

    CURRENT_VERSION=$("$INSTALL_DIR/sub2api" --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    print_info "$(msg 'current_version'): $CURRENT_VERSION"

    # Stop service if running
    if launchctl print system/"$LAUNCHD_LABEL" &>/dev/null; then
        print_info "$(msg 'stopping_service')"
        launchctl bootout system/"$LAUNCHD_LABEL" 2>/dev/null || \
            launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
    fi

    # Backup current binary
    cp "$INSTALL_DIR/sub2api" "$INSTALL_DIR/sub2api.backup"
    print_info "$(msg 'backup_created'): $INSTALL_DIR/sub2api.backup"

    # Download and install new version
    get_latest_version
    download_and_extract

    # Set permissions
    chown "$SERVICE_USER" "$INSTALL_DIR/sub2api"

    # Start service
    print_info "$(msg 'starting_service')"
    launchctl bootstrap system/ "$LAUNCHD_PLIST" 2>/dev/null || \
        launchctl load "$LAUNCHD_PLIST" 2>/dev/null || true

    print_success "$(msg 'upgrade_complete')"
}

# Install specific version (for upgrade or rollback)
# Requires: Sub2API must already be installed
install_version() {
    local target_version="$1"

    if [ ! -f "$INSTALL_DIR/sub2api" ]; then
        print_error "$(msg 'not_installed')"
        print_info "$(msg 'fresh_install_hint'): $SCRIPT_NAME install -v $target_version"
        exit 1
    fi

    # Validate and normalize version
    target_version=$(validate_version "$target_version")

    print_info "$(msg 'installing_version'): $target_version"

    local current_version
    current_version=$(get_current_version)
    print_info "$(msg 'current_version'): $current_version"

    if [ "$current_version" = "$target_version" ] || [ "$current_version" = "${target_version#v}" ]; then
        print_warning "$(msg 'same_version')"
        exit 0
    fi

    # Stop service if running
    if launchctl print system/"$LAUNCHD_LABEL" &>/dev/null; then
        print_info "$(msg 'stopping_service')"
        launchctl bootout system/"$LAUNCHD_LABEL" 2>/dev/null || \
            launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
    fi

    # Backup current binary
    if [ -f "$INSTALL_DIR/sub2api" ]; then
        local backup_name
        if [ "$current_version" != "unknown" ] && [ "$current_version" != "not_installed" ]; then
            backup_name="sub2api.backup.${current_version}"
        else
            backup_name="sub2api.backup.$(date +%Y%m%d%H%M%S)"
        fi
        cp "$INSTALL_DIR/sub2api" "$INSTALL_DIR/$backup_name"
        print_info "$(msg 'backup_created'): $INSTALL_DIR/$backup_name"
    fi

    # Set LATEST_VERSION to the target version for download_and_extract
    LATEST_VERSION="$target_version"

    # Download and install
    download_and_extract

    # Set permissions
    chown "$SERVICE_USER" "$INSTALL_DIR/sub2api"

    # Start service
    print_info "$(msg 'starting_service')"
    if launchctl bootstrap system/ "$LAUNCHD_PLIST" 2>/dev/null || \
       launchctl load "$LAUNCHD_PLIST" 2>/dev/null; then
        print_success "$(msg 'service_started')"
    else
        print_error "$(msg 'service_start_failed')"
        print_info "tail -n 50 ${LOG_DIR}/stderr.log"
    fi

    local new_version
    new_version=$(get_current_version)
    echo ""
    echo "=============================================="
    print_success "$(msg 'install_version_complete')"
    echo "=============================================="
    echo ""
    echo "  $(msg 'current_version'): $new_version"
    echo ""
}

# Uninstall function
uninstall() {
    print_warning "$(msg 'uninstall_confirm')"

    if ! is_interactive; then
        if [ "${FORCE_YES:-}" != "true" ]; then
            print_error "Non-interactive mode detected. Use 'curl ... | sudo zsh -s -- uninstall -y' to confirm."
            exit 1
        fi
    else
        print -n "$(msg 'are_you_sure') "
        read -k 1 REPLY < /dev/tty
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "$(msg 'uninstall_cancelled')"
            exit 0
        fi
    fi

    # Stop and remove launchd service
    print_info "$(msg 'stopping_service')"
    launchctl bootout system/"$LAUNCHD_LABEL" 2>/dev/null || \
        launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true

    print_info "$(msg 'removing_files')"
    rm -f "$LAUNCHD_PLIST"

    print_info "$(msg 'removing_install_dir')"
    rm -rf "$INSTALL_DIR"

    # Remove user and group
    print_info "$(msg 'removing_user')"
    if id "$SERVICE_USER" &>/dev/null; then
        # Remove ONLY our entry from HiddenUsersList — do NOT delete the whole array
        # (defaults delete would wipe all other hidden users on the machine)
        local lw_plist="/Library/Preferences/com.apple.loginwindow.plist"
        local count i val
        count=$(/usr/libexec/PlistBuddy -c "Print :HiddenUsersList" "$lw_plist" 2>/dev/null | grep -c "." || echo 0)
        i=$((count - 1))
        while [ "$i" -ge 0 ]; do
            val=$(/usr/libexec/PlistBuddy -c "Print :HiddenUsersList:${i}" "$lw_plist" 2>/dev/null || true)
            if [ "$val" = "$SERVICE_USER" ]; then
                /usr/libexec/PlistBuddy -c "Delete :HiddenUsersList:${i}" "$lw_plist" 2>/dev/null || true
                break
            fi
            i=$((i - 1))
        done
        dscl . -delete "/Users/$SERVICE_USER" 2>/dev/null || true
        dscl . -delete "/Groups/$SERVICE_USER" 2>/dev/null || true
        dscacheutil -flushcache 2>/dev/null || true
    fi

    # Remove install lock file (.installed) to allow fresh setup on reinstall
    print_info "$(msg 'removing_install_lock')"
    rm -f "$CONFIG_DIR/.installed" 2>/dev/null || true
    rm -f "$INSTALL_DIR/.installed" 2>/dev/null || true
    print_success "$(msg 'install_lock_removed')"

    # Remove log directory
    rm -rf "$LOG_DIR"

    # Ask about config directory removal (interactive mode only)
    local remove_config=false
    if [ "${PURGE:-}" = "true" ]; then
        remove_config=true
    elif is_interactive; then
        print -n "$(msg 'purge_prompt')"
        read -k 1 REPLY < /dev/tty
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            remove_config=true
        fi
    fi

    if [ "$remove_config" = true ]; then
        print_info "$(msg 'removing_config_dir')"
        rm -rf "$CONFIG_DIR"
    else
        print_warning "$(msg 'config_not_removed'): $CONFIG_DIR"
        print_warning "$(msg 'remove_manually')"
    fi

    print_success "$(msg 'uninstall_complete')"
}

# Main
main() {
    # Parse flags first
    local target_version=""
    local positional_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -y|--yes)
                FORCE_YES="true"
                shift
                ;;
            --purge)
                PURGE="true"
                shift
                ;;
            -v|--version)
                if [ -n "${2:-}" ] && [[ ! "$2" =~ ^- ]]; then
                    target_version="$2"
                    shift 2
                else
                    echo "Error: --version requires a version argument"
                    exit 1
                fi
                ;;
            --version=*)
                target_version="${1#*=}"
                if [ -z "$target_version" ]; then
                    echo "Error: --version requires a version argument"
                    exit 1
                fi
                shift
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    # Restore positional arguments
    set -- "${positional_args[@]}"

    # Register global cleanup trap for TEMP_DIR
    trap 'rm -rf "${TEMP_DIR:-}"' EXIT

    # Select language first
    select_language

    echo ""
    echo "=============================================="
    echo "       $(msg 'install_title')"
    echo "=============================================="
    echo ""

    # Parse commands
    case "${1:-}" in
        upgrade|update)
            check_root
            detect_platform
            check_dependencies
            if [ -n "$target_version" ]; then
                install_version "$target_version"
            else
                upgrade
            fi
            exit 0
            ;;
        install)
            check_root
            detect_platform
            check_dependencies
            if [ -n "$target_version" ]; then
                if [ -f "$INSTALL_DIR/sub2api" ]; then
                    install_version "$target_version"
                else
                    configure_server
                    LATEST_VERSION=$(validate_version "$target_version")
                    download_and_extract
                    create_user
                    setup_directories
                    install_service
                    prepare_for_setup
                    get_public_ip
                    start_service
                    enable_autostart
                    print_completion
                fi
            else
                configure_server
                get_latest_version
                download_and_extract
                create_user
                setup_directories
                install_service
                prepare_for_setup
                get_public_ip
                start_service
                enable_autostart
                print_completion
            fi
            exit 0
            ;;
        rollback)
            if [ -z "$target_version" ] && [ -n "${2:-}" ]; then
                target_version="$2"
            fi
            if [ -z "$target_version" ]; then
                print_error "$(msg 'opt_version')"
                echo ""
                echo "Usage: $SCRIPT_NAME rollback -v <version>"
                echo "       $SCRIPT_NAME rollback <version>"
                echo ""
                list_versions
                exit 1
            fi
            check_root
            detect_platform
            check_dependencies
            install_version "$target_version"
            exit 0
            ;;
        list-versions|versions)
            list_versions
            exit 0
            ;;
        uninstall|remove)
            check_root
            uninstall
            exit 0
            ;;
        --help|-h)
            echo "$(msg 'usage'): $SCRIPT_NAME [command] [options]"
            echo ""
            echo "Commands:"
            echo "  $(msg 'cmd_none')            $(msg 'cmd_install')"
            echo "  install              $(msg 'cmd_install')"
            echo "  upgrade              $(msg 'cmd_upgrade')"
            echo "  rollback <version>   $(msg 'cmd_install_version')"
            echo "  list-versions        $(msg 'cmd_list_versions')"
            echo "  uninstall            $(msg 'cmd_uninstall')"
            echo ""
            echo "Options:"
            echo "  -v, --version <ver>  $(msg 'opt_version')"
            echo "  -y, --yes            Skip confirmation prompts (for uninstall)"
            echo ""
            echo "Examples:"
            echo "  $SCRIPT_NAME                        # Install latest version"
            echo "  $SCRIPT_NAME install -v v0.1.0      # Install specific version"
            echo "  $SCRIPT_NAME upgrade                # Upgrade to latest"
            echo "  $SCRIPT_NAME upgrade -v v0.2.0      # Upgrade to specific version"
            echo "  $SCRIPT_NAME rollback v0.1.0        # Rollback to v0.1.0"
            echo "  $SCRIPT_NAME list-versions          # List available versions"
            echo ""
            exit 0
            ;;
    esac

    # Default: Fresh install with latest version
    check_root
    detect_platform
    check_dependencies

    if [ -n "$target_version" ]; then
        if [ -f "$INSTALL_DIR/sub2api" ]; then
            install_version "$target_version"
        else
            configure_server
            LATEST_VERSION=$(validate_version "$target_version")
            download_and_extract
            create_user
            setup_directories
            install_service
            prepare_for_setup
            get_public_ip
            start_service
            enable_autostart
            print_completion
        fi
    else
        configure_server
        get_latest_version
        download_and_extract
        create_user
        setup_directories
        install_service
        prepare_for_setup
        get_public_ip
        start_service
        enable_autostart
        print_completion
    fi
}

main "$@"
