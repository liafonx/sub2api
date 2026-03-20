#!/bin/zsh
#
# deploy/migrate-macos-homebrew.sh
# One-time migration: /opt/sub2api (LaunchDaemon, sub2api user)
#                  → /usr/local/var/sub2api (LaunchAgent, liafonx user)
#
# Run as: liafonx (not root). Uses sudo only for privileged steps.
# Usage:  zsh deploy/migrate-macos-homebrew.sh
#
# Rollback (before cleanup step):
#   launchctl bootout gui/$(id -u)/com.sub2api
#   rm ~/Library/LaunchAgents/com.sub2api.plist
#   sudo launchctl bootstrap system /Library/LaunchDaemons/com.sub2api.plist
#

set -e

# ============================================================
# Constants
# ============================================================
OLD_DIR="/opt/sub2api"
OLD_PLIST="/Library/LaunchDaemons/com.sub2api.plist"
OLD_LOG_DIR="/var/log/sub2api"
LOGROTATE_CONF="/usr/local/etc/logrotate.d/sub2api.conf"

NEW_BIN="/usr/local/bin/sub2api"
DATA_DIR="/usr/local/var/sub2api"
LOG_DIR="/usr/local/var/log/sub2api"
PLIST="$HOME/Library/LaunchAgents/com.sub2api.plist"
LABEL="com.sub2api"

# ============================================================
# Helpers
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ============================================================
# Step 1: Pre-flight checks
# ============================================================
preflight() {
    info "Running pre-flight checks..."

    [[ "$(whoami)" == "liafonx" ]] || \
        die "Must run as liafonx, not $(whoami). Do NOT use sudo."

    [[ -f "$OLD_DIR/sub2api" ]] || \
        die "Old binary not found at $OLD_DIR/sub2api. Is sub2api installed?"

    [[ -d /usr/local/bin ]] || \
        die "/usr/local/bin does not exist. Install Homebrew first."

    [[ -w /usr/local/bin ]] || \
        die "/usr/local/bin is not writable by liafonx.\nFix: sudo chown -R liafonx:admin /usr/local/bin"

    # /usr/local/var may not exist yet (will be created) — only check if it exists
    if [[ -d /usr/local/var ]] && [[ ! -w /usr/local/var ]]; then
        die "/usr/local/var is not writable by liafonx.\nFix: sudo chown -R liafonx:admin /usr/local/var"
    fi

    # Check auto-login is configured (required for LaunchAgent to start at boot)
    local autologin
    autologin=$(sudo defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "")
    if [[ -z "$autologin" ]]; then
        warn "Auto-login is NOT configured. LaunchAgent will not start after reboot until you log in."
        warn "Set it in: System Preferences > Users & Groups > Login Options > Automatic Login > liafonx"
        echo -n "Continue anyway? (y/N): "
        read -r REPLY < /dev/tty
        [[ "$REPLY" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
    else
        success "Auto-login configured for: $autologin"
    fi

    success "Pre-flight passed"
}

# ============================================================
# Step 2: Stop current LaunchDaemon
# ============================================================
stop_daemon() {
    info "Stopping LaunchDaemon $LABEL..."

    if sudo launchctl print system/"$LABEL" &>/dev/null; then
        sudo launchctl bootout system/"$LABEL" 2>/dev/null || \
            sudo launchctl unload "$OLD_PLIST" 2>/dev/null || true
    else
        info "LaunchDaemon not currently running"
    fi

    # Wait for process to exit (max 10s)
    local waited=0
    while pgrep -x sub2api &>/dev/null && [[ $waited -lt 10 ]]; do
        sleep 1
        waited=$((waited + 1))
    done

    if pgrep -x sub2api &>/dev/null; then
        die "sub2api process still running after ${waited}s. Kill it manually: sudo pkill sub2api"
    fi

    success "Service stopped"
}

# ============================================================
# Step 3: Create new directory structure
# ============================================================
create_dirs() {
    info "Creating Homebrew-style directories..."

    mkdir -p "$DATA_DIR/data"
    mkdir -p "$LOG_DIR"
    mkdir -p "$HOME/Library/LaunchAgents"

    success "Directories created"
}

# ============================================================
# Steps 4-5: Copy artifacts
# ============================================================
copy_artifacts() {
    info "Copying binary to /usr/local/bin/..."
    cp "$OLD_DIR/sub2api" "$NEW_BIN"
    chmod +x "$NEW_BIN"

    info "Copying config.yaml..."
    cp "$OLD_DIR/config.yaml" "$DATA_DIR/config.yaml"

    info "Copying data directory (sudo for root-owned sora dirs)..."
    # sudo cp -a preserves ownership metadata; chown step below normalizes it
    sudo cp -a "$OLD_DIR/data/." "$DATA_DIR/data/"

    if [[ -f "$OLD_DIR/.installed" ]]; then
        info "Copying .installed lock..."
        cp "$OLD_DIR/.installed" "$DATA_DIR/.installed"
    fi

    success "Artifacts copied"
}

# ============================================================
# Step 6: Patch config.yaml paths
# ============================================================
patch_config() {
    info "Patching config.yaml..."

    # Update sora local_path
    sed -i '' \
        's|local_path: "/opt/sub2api/data/sora"|local_path: "/usr/local/var/sub2api/data/sora"|g' \
        "$DATA_DIR/config.yaml"

    # Update server.mode from debug to release if needed
    sed -i '' \
        's|mode: "debug"|mode: "release"|g' \
        "$DATA_DIR/config.yaml"

    success "config.yaml patched"
}

# ============================================================
# Step 7: Copy log files
# ============================================================
copy_logs() {
    info "Copying log files..."

    sudo sh -c "cp ${OLD_LOG_DIR}/*.log ${LOG_DIR}/ 2>/dev/null || true"
    sudo sh -c "cp ${OLD_LOG_DIR}/*.gz ${LOG_DIR}/ 2>/dev/null || true"

    success "Logs copied"
}

# ============================================================
# Step 8: Fix ownership to liafonx:staff
# ============================================================
fix_ownership() {
    info "Fixing ownership to liafonx:staff..."

    sudo chown liafonx:admin "$NEW_BIN"
    sudo chown -R liafonx:admin "$DATA_DIR"
    sudo chown -R liafonx:admin "$LOG_DIR"

    success "Ownership fixed"
}

# ============================================================
# Step 9: Clear macOS quarantine attribute
# ============================================================
clear_quarantine() {
    xattr -d com.apple.quarantine "$NEW_BIN" 2>/dev/null || true
    success "Quarantine cleared (or not present)"
}

# ============================================================
# Step 10: Write LaunchAgent plist
# ============================================================
write_plist() {
    info "Writing LaunchAgent plist to $PLIST..."

    cat > "$PLIST" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sub2api</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/sub2api</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/usr/local/var/sub2api</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/sub2api/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/sub2api/stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GIN_MODE</key>
        <string>release</string>
    </dict>
</dict>
</plist>
PLIST_EOF

    # Validate plist syntax
    plutil -lint "$PLIST" || die "Plist validation failed"

    success "Plist written and validated"
}

# ============================================================
# Step 11: Load LaunchAgent and verify
# ============================================================
load_and_verify() {
    info "Loading LaunchAgent..."

    local uid
    uid=$(id -u)

    # Unload first in case of stale entry
    launchctl bootout "gui/$uid/$LABEL" 2>/dev/null || true

    launchctl bootstrap "gui/$uid" "$PLIST" || die "launchctl bootstrap failed. Check: plutil -lint $PLIST"

    info "Waiting 3s for service to start..."
    sleep 3

    if launchctl print "gui/$uid/$LABEL" &>/dev/null; then
        success "LaunchAgent is running (PID confirmed)"
    else
        die "LaunchAgent failed to start. Check: tail -20 $LOG_DIR/stderr.log"
    fi

    # Health check
    if curl -sf http://127.0.0.1:9876/health &>/dev/null; then
        success "Health check passed: http://127.0.0.1:9876/health"
    else
        warn "Health check failed or timed out — service may still be initializing."
        warn "Check: tail -20 $LOG_DIR/stderr.log"
        warn "If the service is starting up, wait a moment then: curl -sf http://127.0.0.1:9876/health"
    fi
}

# ============================================================
# Step 12: Update logrotate config
# ============================================================
update_logrotate() {
    if [[ ! -f "$LOGROTATE_CONF" ]]; then
        warn "Logrotate config not found at $LOGROTATE_CONF, skipping"
        return
    fi

    info "Updating logrotate config..."

    # Backup before editing
    sudo cp "$LOGROTATE_CONF" /tmp/sub2api-logrotate.conf.bak

    sudo sed -i '' \
        -e 's|/var/log/sub2api|/usr/local/var/log/sub2api|g' \
        -e 's|su sub2api wheel|su liafonx staff|g' \
        "$LOGROTATE_CONF"

    success "Logrotate updated (backup at /tmp/sub2api-logrotate.conf.bak)"
}

# ============================================================
# Step 13: Backup old artifacts before cleanup
# ============================================================
backup_old() {
    info "Backing up old artifacts for rollback..."

    if [[ -f "$OLD_PLIST" ]]; then
        sudo cp "$OLD_PLIST" /tmp/com.sub2api.plist.bak
        success "Old LaunchDaemon plist backed up to /tmp/com.sub2api.plist.bak"
    else
        warn "Old plist not found at $OLD_PLIST (already removed?)"
    fi
}

# ============================================================
# Step 14: Interactive cleanup of old installation
# ============================================================
cleanup() {
    echo ""
    echo "============================================================"
    warn "CLEANUP: The following will be PERMANENTLY DELETED:"
    echo "  /Library/LaunchDaemons/com.sub2api.plist"
    echo "  /opt/sub2api/ (entire directory)"
    echo "  /etc/sub2api/ (if it exists)"
    echo "  /var/log/sub2api/"
    echo "  dscl user:  sub2api"
    echo "  dscl group: sub2api"
    echo "============================================================"
    echo ""
    echo "Only proceed after verifying the new installation works."
    echo -n "Type 'yes' to permanently delete old artifacts: "
    read -r REPLY < /dev/tty

    if [[ "$REPLY" != "yes" ]]; then
        info "Cleanup skipped. Old installation preserved at $OLD_DIR"
        info "Run this script again and type 'yes' when ready."
        return
    fi

    info "Removing old LaunchDaemon plist..."
    sudo rm -f "$OLD_PLIST"

    info "Removing /opt/sub2api/..."
    sudo rm -rf "$OLD_DIR"

    info "Removing /etc/sub2api/ (if exists)..."
    sudo rmdir /etc/sub2api 2>/dev/null || true

    info "Removing /var/log/sub2api/..."
    sudo rm -rf "$OLD_LOG_DIR"

    info "Removing sub2api dscl user and group..."
    if id sub2api &>/dev/null; then
        # Remove ONLY our entry from HiddenUsersList to avoid wiping other hidden users
        local lw_plist="/Library/Preferences/com.apple.loginwindow.plist"
        local count i val
        count=$(/usr/libexec/PlistBuddy -c "Print :HiddenUsersList" "$lw_plist" 2>/dev/null | grep -c "." || echo 0)
        i=$((count - 1))
        while [[ $i -ge 0 ]]; do
            val=$(/usr/libexec/PlistBuddy -c "Print :HiddenUsersList:${i}" "$lw_plist" 2>/dev/null || true)
            if [[ "$val" == "sub2api" ]]; then
                sudo /usr/libexec/PlistBuddy -c "Delete :HiddenUsersList:${i}" "$lw_plist" 2>/dev/null || true
                break
            fi
            i=$((i - 1))
        done

        sudo dscl . -delete /Users/sub2api 2>/dev/null || true
        sudo dscl . -delete /Groups/sub2api 2>/dev/null || true
        sudo dscacheutil -flushcache 2>/dev/null || true
        success "sub2api user and group removed"
    else
        info "sub2api user not found, skipping"
    fi

    success "Cleanup complete"
}

# ============================================================
# Summary
# ============================================================
print_summary() {
    echo ""
    echo "============================================================"
    success "Migration complete!"
    echo "============================================================"
    echo ""
    echo "New layout:"
    echo "  Binary:      /usr/local/bin/sub2api"
    echo "  Data/Config: /usr/local/var/sub2api/"
    echo "  Logs:        /usr/local/var/log/sub2api/"
    echo "  Plist:       $HOME/Library/LaunchAgents/com.sub2api.plist"
    echo ""
    echo "Service management (no sudo required):"
    echo "  Status:   launchctl print gui/\$(id -u)/com.sub2api"
    echo "  Stop:     launchctl bootout gui/\$(id -u)/com.sub2api"
    echo "  Start:    launchctl bootstrap gui/\$(id -u) ~/Library/LaunchAgents/com.sub2api.plist"
    echo "  Logs:     tail -f /usr/local/var/log/sub2api/stderr.log"
    echo ""
    echo "Rollback (if not yet cleaned up):"
    echo "  launchctl bootout gui/\$(id -u)/com.sub2api"
    echo "  rm ~/Library/LaunchAgents/com.sub2api.plist"
    echo "  sudo launchctl bootstrap system /Library/LaunchDaemons/com.sub2api.plist"
    echo ""
    echo "After reboot, verify auto-login brings the service back up:"
    echo "  launchctl print gui/\$(id -u)/com.sub2api"
    echo "  curl -sf http://127.0.0.1:9876/health"
    echo ""
}

# ============================================================
# Main
# ============================================================
main() {
    echo ""
    echo "============================================================"
    echo "  sub2api: Migrate to Homebrew-style layout"
    echo "============================================================"
    echo ""

    preflight
    stop_daemon
    create_dirs
    copy_artifacts
    patch_config
    copy_logs
    fix_ownership
    clear_quarantine
    write_plist
    load_and_verify
    update_logrotate
    backup_old
    print_summary
    cleanup
}

main "$@"
