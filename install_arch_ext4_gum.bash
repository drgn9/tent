#!/usr/bin/env bash

clear

set -euo pipefail

if [[ ${EUID:-0} -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

####################################################################################################
# UEFI check
####################################################################################################

if [[ ! -d /sys/firmware/efi/efivars ]]; then
    echo "ERROR: This script requires UEFI boot mode. Legacy BIOS is not supported."
    exit 1
fi

####################################################################################################
# Dependencies
####################################################################################################

deps_needed=()
command -v gum &>/dev/null || deps_needed+=("gum")
command -v reflector &>/dev/null || deps_needed+=("reflector")
command -v cryptsetup &>/dev/null || deps_needed+=("cryptsetup")
command -v efibootmgr &>/dev/null || deps_needed+=("efibootmgr")

if [[ ${#deps_needed[@]} -gt 0 ]]; then
    echo "Installing dependencies: ${deps_needed[*]}"
    pacman -Syu --noconfirm "${deps_needed[@]}" &>/dev/null
fi

####################################################################################################
# Helper functions
####################################################################################################

show_header() {
    clear
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 70 --margin "1 2" --padding "1 2" \
        "Arch Linux Installer (ext4)" \
        "" \
        " / \   _ __ ___| |__   | |   (_)_ __  _   ___  __" \
        "/ _ \ | '__/ __| '_ \  | |   | | '_ \| | | \ \/ /" \
        "/ ___ \| | | (__| | | | | |___| | | | | |_| |>  <" \
        "/_/   \_\_|  \___|_| |_| |_____|_|_| |_|\__,_/_/\_\\"
}

show_info() {
    gum log --level info "$1"
}

show_error() {
    gum log --level error "$1"
}

show_warn() {
    gum log --level warn "$1"
}

required_paths=(
    /root/tent/settings/network/NetworkManager.conf
    /root/tent/settings/network/20-wired.network
    /root/tent/settings/network/wait-for-only-one-interface.conf
    /root/tent/settings/network/25-wireless.network
    /root/tent/settings/network/iwd.main.conf
    /root/tent/settings/network/iwd.override.conf
    /root/tent/settings/network/resolved.conf
    /root/tent/settings/sysctl/99-firewall-settings.conf
    /root/tent/settings/sysctl/99-watchdog-settings.conf
    /root/tent/settings/sysctl/99-zram-settings.conf
    /root/tent/settings/sysctl/99-hardening.conf
    /root/tent/settings/modprobe/blacklist.conf
    /root/tent/settings/modprobe/disable-firewire.conf
    /root/tent/settings/modprobe/iwlwifi.conf
    /root/tent/settings/modprobe/security-blacklist.conf
    /root/tent/settings/modprobe/disable-bluetooth.conf
    /root/tent/settings/modprobe/disable-thunderbolt.conf
    /root/tent/settings/systemd/disable-coredump-system.conf
    /root/tent/settings/systemd/disable-coredump-user.conf
    /root/tent/settings/security/disable-coredump.conf
    /root/tent/settings/polkit/00-udisks-wheel.rules
    /root/tent/settings/run0/sudo-wrapper
    /root/tent/settings/run0/90-run0.rules
    /root/tent/settings/run0/polkitd.conf
    /root/tent/settings/run0/harden-suid
    /root/tent/settings/run0/99-harden-suid.hook
)

missing_paths=()
for path in "${required_paths[@]}"; do
    if [[ ! -e "$path" ]]; then
        missing_paths+=("$path")
    fi
done

if [[ ${#missing_paths[@]} -gt 0 ]]; then
    show_error "Missing required settings files:"
    printf '%s\n' "${missing_paths[@]}"
    exit 1
fi

####################################################################################################
# Error handling
####################################################################################################

cleanup() {
    show_error "Installation failed at line $1"
    rm -f /mnt/etc/sudoers.d/wheel 2>/dev/null || true
    umount -R /mnt 2>/dev/null || true
    cryptsetup close cryptroot 2>/dev/null || true
}
trap 'cleanup $LINENO' ERR

####################################################################################################
# Installer functions (settings)
####################################################################################################

apparmor_installer() {
    if [ "$use_apparmor" = "yes" ]; then
        pacstrap /mnt apparmor >/dev/null
        cat > /mnt/etc/cmdline.d/security.conf <<EOF
# enable apparmor
lsm=landlock,lockdown,yama,integrity,apparmor,bpf audit=1 audit_backlog_limit=256
EOF
        systemctl enable apparmor.service --root=/mnt &>/dev/null
        systemctl enable auditd.service --root=/mnt &>/dev/null
        echo "write-cache" >> /mnt/etc/apparmor/parser.conf
        echo "Optimize=compress-fast" >> /mnt/etc/apparmor/parser.conf
    else
        cat > /mnt/etc/cmdline.d/security.conf <<EOF
# apparmor disabled
# lsm=landlock,lockdown,yama,integrity,apparmor,bpf audit=1 audit_backlog_limit=256
EOF
    fi
}

network_installer() {
    case $network_choice in
        1)
            show_info "Enabling systemd-networkd, installing and enabling iwd"
            pacstrap /mnt iwd >/dev/null
            systemctl enable systemd-networkd.service --root=/mnt &>/dev/null
            systemctl enable iwd.service --root=/mnt &>/dev/null
            set_systemd_networkd
            set_iwd
            ;;
        2)
            show_info "Enabling systemd-networkd"
            systemctl enable systemd-networkd.service --root=/mnt &>/dev/null
            set_systemd_networkd
            ;;
        3)
            show_info "Installing and enabling NetworkManager"
            pacstrap /mnt networkmanager network-manager-applet nm-connection-editor >/dev/null
            cp /root/tent/settings/network/NetworkManager.conf /mnt/etc/NetworkManager/NetworkManager.conf
            systemctl enable NetworkManager.service --root=/mnt &>/dev/null
            ;;
    esac
}

microcode_detector() {
    CPU=$(grep -m1 vendor_id /proc/cpuinfo)
    if [[ "$CPU" == *"AuthenticAMD"* ]]; then
        show_info "AMD CPU detected, AMD microcode will be installed"
        microcode="amd-ucode"
    else
        show_info "Intel CPU detected, Intel microcode will be installed"
        microcode="intel-ucode"
    fi
}

set_sysctl() {
    cp /root/tent/settings/sysctl/99-firewall-settings.conf /mnt/etc/sysctl.d/99-firewall-settings.conf
    cp /root/tent/settings/sysctl/99-watchdog-settings.conf /mnt/etc/sysctl.d/99-watchdog-settings.conf
    cp /root/tent/settings/sysctl/99-zram-settings.conf /mnt/etc/sysctl.d/99-zram-settings.conf
    cp /root/tent/settings/sysctl/99-hardening.conf /mnt/etc/sysctl.d/99-hardening.conf
}

set_modprobe() {
    cp /root/tent/settings/modprobe/blacklist.conf /mnt/etc/modprobe.d/blacklist.conf
    cp /root/tent/settings/modprobe/disable-firewire.conf /mnt/etc/modprobe.d/disable-firewire.conf
    cp /root/tent/settings/modprobe/iwlwifi.conf /mnt/etc/modprobe.d/iwlwifi.conf
    cp /root/tent/settings/modprobe/security-blacklist.conf /mnt/etc/modprobe.d/security-blacklist.conf
    if [ "$use_bluetooth" = "no" ]; then
        cp /root/tent/settings/modprobe/disable-bluetooth.conf /mnt/etc/modprobe.d/disable-bluetooth.conf
    fi
    if [ "$use_thunderbolt" = "no" ]; then
        cp /root/tent/settings/modprobe/disable-thunderbolt.conf /mnt/etc/modprobe.d/disable-thunderbolt.conf
    fi
}

set_coredump() {
    mkdir -p /mnt/etc/systemd/system.conf.d
    mkdir -p /mnt/etc/systemd/user.conf.d
    mkdir -p /mnt/etc/security/limits.d
    cp /root/tent/settings/systemd/disable-coredump-system.conf /mnt/etc/systemd/system.conf.d/60-disable-coredump.conf
    cp /root/tent/settings/systemd/disable-coredump-user.conf /mnt/etc/systemd/user.conf.d/60-disable-coredump.conf
    cp /root/tent/settings/security/disable-coredump.conf /mnt/etc/security/limits.d/60-disable-coredump.conf
}

set_run0() {
    # Deploy sudo wrapper (intercepts all sudo calls, redirects to run0)
    cp /root/tent/settings/run0/sudo-wrapper /mnt/usr/local/bin/sudo
    chmod 755 /mnt/usr/local/bin/sudo
    chown root:root /mnt/usr/local/bin/sudo

    # Deploy polkit rules (wheel group auth with 5-minute caching)
    mkdir -p /mnt/etc/polkit-1/rules.d
    cp /root/tent/settings/run0/90-run0.rules /mnt/etc/polkit-1/rules.d/90-run0.rules

    # Deploy polkit cache timeout config
    cp /root/tent/settings/run0/polkitd.conf /mnt/etc/polkit-1/polkitd.conf

    # Deploy SUID hardening script
    cp /root/tent/settings/run0/harden-suid /mnt/usr/local/bin/harden-suid
    chmod 755 /mnt/usr/local/bin/harden-suid
    chown root:root /mnt/usr/local/bin/harden-suid

    # Deploy pacman hook (runs harden-suid after every package install/upgrade)
    mkdir -p /mnt/etc/pacman.d/hooks
    cp /root/tent/settings/run0/99-harden-suid.hook /mnt/etc/pacman.d/hooks/99-harden-suid.hook

    # Add PACMAN_AUTH and alias to user's .bashrc
    cat >> /mnt/home/"$username"/.bashrc <<'BASHRC'

# run0 as privilege escalation tool
export PACMAN_AUTH="run0"
alias sudo='run0'
BASHRC

    # Lock down sudoers — remove wheel group access
    echo "# sudoers locked — using run0 for privilege escalation" > /mnt/etc/sudoers.d/wheel
    arch-chroot /mnt chmod 0440 /etc/sudoers.d/wheel

    # Run the initial SUID/SGID stripping + capability application
    show_info "Stripping SUID/SGID bits and applying capabilities"
    arch-chroot /mnt /usr/local/bin/harden-suid
}

set_systemd_networkd() {
    mkdir -p /mnt/etc/systemd/network
    mkdir -p /mnt/etc/systemd/system/systemd-networkd-wait-online.service.d
    cp /root/tent/settings/network/20-wired.network /mnt/etc/systemd/network/20-wired.network
    cp /root/tent/settings/network/wait-for-only-one-interface.conf /mnt/etc/systemd/system/systemd-networkd-wait-online.service.d/wait-for-only-one-interface.conf
    if [[ -f /mnt/etc/systemd/networkd.conf ]]; then
        sed -i '/^#ManageForeignRoutingPolicyRules=yes/c\ManageForeignRoutingPolicyRules=no' /mnt/etc/systemd/networkd.conf
    else
        cat > /mnt/etc/systemd/networkd.conf <<EOF
[Network]
ManageForeignRoutingPolicyRules=no
EOF
    fi
}

set_iwd() {
    mkdir -p /mnt/etc/systemd/network
    mkdir -p /mnt/etc/iwd
    mkdir -p /mnt/etc/systemd/system/iwd.service.d
    cp /root/tent/settings/network/25-wireless.network /mnt/etc/systemd/network/25-wireless.network
    cp /root/tent/settings/network/iwd.main.conf /mnt/etc/iwd/main.conf
    cp /root/tent/settings/network/iwd.override.conf /mnt/etc/systemd/system/iwd.service.d/override.conf
    if [[ -d /var/lib/iwd ]]; then
        cp -r /var/lib/iwd /mnt/var/lib
    fi
}

set_systemd_resolved() {
    ln -sf /run/systemd/resolve/stub-resolv.conf /mnt/etc/resolv.conf
    cp /root/tent/settings/network/resolved.conf /mnt/etc/systemd/resolved.conf
    systemctl enable systemd-resolved --root=/mnt &>/dev/null
}

####################################################################################################
# Begin Installation
####################################################################################################

show_header

####################################################################################################
# Keyring and clock
####################################################################################################

gum spin --spinner dot --title "Updating keyring and synchronizing clock..." -- \
    bash -c 'timedatectl set-ntp true && pacman -Syu --noconfirm archlinux-keyring >/dev/null'
show_info "Keyring updated and clock synchronized"

kblayout="us"
show_info "Setting console layout to $kblayout"
loadkeys "$kblayout"

####################################################################################################
# User prompts
####################################################################################################

# --- LUKS encryption ---
gum style --foreground 212 --bold --margin "1 0" "LUKS Encryption"
if gum confirm "Encrypt the root partition?"; then
    encrypt_root="yes"
    show_info "Root encryption: enabled"
else
    encrypt_root="no"
    show_info "Root encryption: disabled"
fi

# --- Unlock method ---
fido2_backup="no"
if [ "$encrypt_root" = "yes" ]; then
    unlock_method=$(gum choose --header "Select LUKS unlock method:" \
        "TPM2 + PIN" \
        "FIDO2 + PIN" \
        "Passphrase only")

    case "$unlock_method" in
        "TPM2 + PIN")
            unlock_method="tpm2"
            show_info "Unlock method: TPM2 + PIN"
            ;;
        "FIDO2 + PIN")
            unlock_method="fido2"
            show_info "Unlock method: FIDO2 + PIN"
            if gum confirm "Enroll a backup FIDO2 key?"; then
                fido2_backup="yes"
                show_info "Backup FIDO2 key: enabled"
            else
                show_info "Backup FIDO2 key: disabled"
            fi
            ;;
        "Passphrase only")
            unlock_method="passphrase"
            show_info "Unlock method: passphrase"
            ;;
    esac
else
    unlock_method="none"
fi

# --- Secure Boot ---
gum style --foreground 212 --bold --margin "1 0" "Secure Boot"
if gum confirm "Enable Secure Boot?"; then
    secure_boot="yes"
    show_info "Secure Boot: enabled"

    # Check Setup Mode
    setup_mode=$(od -An -t u1 -j4 -N1 /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')
    if [ "$setup_mode" != "1" ]; then
        gum style --foreground 196 --bold --margin "1 2" \
            "Secure Boot Setup Mode is NOT enabled." \
            "You must enter Setup Mode before running this script with Secure Boot."
        gum style --foreground 212 --margin "0 2" \
            "To enable Setup Mode:" \
            "  1. Reboot into firmware setup: systemctl reboot --firmware-setup" \
            "  2. Navigate to the Secure Boot settings" \
            "  3. Delete/clear all Secure Boot keys (PK, KEK, db)" \
            "  4. Ensure Secure Boot remains enabled" \
            "  5. Save and exit, then re-run this script"
        exit 1
    fi
    show_info "Secure Boot Setup Mode is enabled"
else
    secure_boot="no"
    show_info "Secure Boot: disabled"
fi

# --- AppArmor ---
gum style --foreground 212 --bold --margin "1 0" "AppArmor"
if gum confirm "Enable AppArmor?"; then
    use_apparmor="yes"
    show_info "AppArmor: enabled"
else
    use_apparmor="no"
    show_info "AppArmor: disabled"
fi

# --- Kernel Lockdown ---
gum style --foreground 212 --bold --margin "1 0" "Kernel Lockdown"
if gum confirm "Enable kernel lockdown (integrity mode)?"; then
    use_lockdown="yes"
    show_info "Kernel lockdown: enabled (integrity)"
else
    use_lockdown="no"
    show_info "Kernel lockdown: disabled"
fi

# --- Hardware ---
gum style --foreground 212 --bold --margin "1 0" "Hardware"
if gum confirm "Disable bluetooth?"; then
    use_bluetooth="no"
    show_info "Bluetooth: disabled"
else
    use_bluetooth="yes"
    show_info "Bluetooth: enabled"
fi

if gum confirm "Disable thunderbolt?"; then
    use_thunderbolt="no"
    show_info "Thunderbolt: disabled"
else
    use_thunderbolt="yes"
    show_info "Thunderbolt: enabled"
fi

# --- run0 (sudo replacement) ---
gum style --foreground 212 --bold --margin "1 0" "Privilege Escalation"
if gum confirm "Replace sudo with run0? (SUID hardening + polkit auth)"; then
    use_run0="yes"
    show_info "Privilege escalation: run0 (sudo replaced, SUID hardened)"
else
    use_run0="no"
    show_info "Privilege escalation: sudo (default)"
fi

# --- Network ---
gum style --foreground 212 --bold --margin "1 0" "Network"
network_selection=$(gum choose --header "Select network configuration:" \
    "iwd + systemd-networkd" \
    "systemd-networkd only" \
    "NetworkManager")

case "$network_selection" in
    "iwd + systemd-networkd")   network_choice=1 ;;
    "systemd-networkd only")    network_choice=2 ;;
    "NetworkManager")           network_choice=3 ;;
esac
show_info "Network: $network_selection"

# --- Hostname ---
gum style --foreground 212 --bold --margin "1 0" "Hostname"
while true; do
    hostname=$(gum input --header "Enter hostname:" --placeholder "archlinux" --char-limit 63)
    if [[ -z "$hostname" ]]; then
        show_error "You need to enter a hostname"
        continue
    fi
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        show_error "Invalid hostname. Use only letters, digits, and hyphens. Must not start or end with a hyphen."
        continue
    fi
    break
done
show_info "Hostname: $hostname"

# --- Timezone ---
gum style --foreground 212 --bold --margin "1 0" "Timezone"
tz_region=$(find /usr/share/zoneinfo -maxdepth 1 -type d \
    -not -name 'zoneinfo' -not -name 'posix' -not -name 'right' \
    -printf '%f\n' 2>/dev/null | sort | \
    gum filter --header "Select region:" --placeholder "Search region..." --height 15)

tz_city=$(find "/usr/share/zoneinfo/$tz_region" -type f -printf '%P\n' 2>/dev/null | sort | \
    gum filter --header "Select city:" --placeholder "Search city..." --height 15)

timezone="$tz_region/$tz_city"
show_info "Timezone: $timezone"

# --- Mirror country ---
gum style --foreground 212 --bold --margin "1 0" "Mirror Country"
reflector_country=$(reflector --list-countries 2>/dev/null | tail -n +3 | \
    sed 's/\s\+[A-Z]\{2\}\s\+[0-9]\+\s*$//' | \
    gum filter --header "Select mirror country:" --placeholder "Search country..." --height 15)

show_info "Mirror country: $reflector_country"

# --- User account ---
gum style --foreground 212 --bold --margin "1 0" "User Account"
while true; do
    username=$(gum input --header "Enter username:" --placeholder "user")
    if [[ -z "$username" ]]; then
        show_error "You need to enter a username"
        continue
    fi
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        show_error "Invalid username. Use lowercase letters, digits, underscores, or hyphens. Must start with a letter or underscore (max 32 chars)."
        continue
    fi
    break
done
show_info "Username: $username"

while true; do
    userpass=$(gum input --password --header "Enter password for $username:")
    if [[ -z "$userpass" ]]; then
        show_error "You need to enter a password"
        continue
    fi
    userpass2=$(gum input --password --header "Confirm password for $username:")
    if [[ "$userpass" != "$userpass2" ]]; then
        show_error "Passwords don't match, please try again"
        continue
    fi
    break
done
show_info "Password set for $username"

####################################################################################################
# Pre-install summary
####################################################################################################

gum style --foreground 212 --bold --margin "1 0" "Installation Summary"

encrypt_label="no"
[ "$encrypt_root" = "yes" ] && encrypt_label="yes (LUKS)"

unlock_label="none"
case "$unlock_method" in
    tpm2)       unlock_label="TPM2 + PIN (with recovery key)" ;;
    fido2)
        if [ "$fido2_backup" = "yes" ]; then
            unlock_label="FIDO2 + PIN (primary + backup key, with recovery key)"
        else
            unlock_label="FIDO2 + PIN (with recovery key)"
        fi
        ;;
    passphrase) unlock_label="passphrase" ;;
esac

gum style --border rounded --border-foreground 212 --padding "1 2" --margin "0 2" \
    "Encryption:      $encrypt_label" \
    "Unlock method:   $unlock_label" \
    "Secure Boot:     $secure_boot" \
    "AppArmor:        $use_apparmor" \
    "Lockdown:        $use_lockdown" \
    "Bluetooth:       $use_bluetooth" \
    "Thunderbolt:     $use_thunderbolt" \
    "run0 (sudo):     $use_run0" \
    "Network:         $network_selection" \
    "Hostname:        $hostname" \
    "Timezone:        $timezone" \
    "Mirrors:         $reflector_country" \
    "Username:        $username"

echo ""
if ! gum confirm "Proceed with installation?"; then
    show_info "Installation cancelled"
    exit 0
fi

####################################################################################################
# Secure wipe disks
####################################################################################################

gum style --foreground 212 --bold --margin "1 0" "Secure Wipe Disks"

while true; do
    devices=$(lsblk --nodeps --paths --list --noheadings --sort=size --output=name,size,model | grep --invert-match "loop")

    if [[ -z "$devices" ]]; then
        show_warn "No devices found"
        break
    fi

    device=$(echo -e "Skip\n$devices" | gum choose --header "Select device to securely wipe (or Skip):")

    if [[ "$device" = "Skip" ]]; then
        break
    fi

    device_path=$(echo "$device" | awk '{print $1}')
    show_info "Wiping $device_path"
    wipefs --all "$device_path"
    cryptsetup open --type plain -c aes-xts-plain64 -d /dev/urandom "$device_path" to_be_wiped
    dd if=/dev/zero of=/dev/mapper/to_be_wiped bs=1M status=progress || true
    cryptsetup close /dev/mapper/to_be_wiped
    show_info "Secure wipe complete for $device_path"
done

####################################################################################################
# Partition disks
####################################################################################################

gum style --foreground 212 --bold --margin "1 0" "Partition Disks"

while true; do
    devices=$(lsblk --nodeps --paths --list --noheadings --sort=size --output=name,size,model | grep --invert-match "loop")

    if [[ -z "$devices" ]]; then
        show_warn "No devices found"
        break
    fi

    device=$(echo -e "Skip\n$devices" | gum choose --header "Select device to partition (or Skip):")

    if [[ "$device" = "Skip" ]]; then
        break
    fi

    device_path=$(echo "$device" | awk '{print $1}')
    show_info "Opening fdisk for $device_path"
    fdisk "$device_path" || true
done

# Build partition list for selection
partitions=$(lsblk --paths --list --noheadings --output=name,size,model,type,fstype,mountpoints | awk '$4 == "part"')

if [[ -z "$partitions" ]]; then
    show_error "No partitions found. Please partition a disk first."
    exit 1
fi

# --- EFI partition ---
gum style --foreground 212 --bold --margin "1 0" "Select Partitions"

efi_part=$(echo "$partitions" | gum choose --header "Select the EFI partition:" | awk '{print $1}')
show_info "EFI partition: $efi_part"

# --- Root partition ---
root_part=$(echo "$partitions" | gum choose --header "Select the root partition:" | awk '{print $1}')
show_info "Root partition: $root_part"

# --- Snapshot partition ---
if gum confirm "Mount a snapshot partition?"; then
    use_snap_part="yes"
    snap_part=$(echo "$partitions" | gum choose --header "Select the snapshot partition:" | awk '{print $1}')
    show_info "Snapshot partition: $snap_part"
else
    use_snap_part="no"
fi

# Validate partitions are different
if [[ "$efi_part" = "$root_part" ]]; then
    show_error "EFI and root partitions cannot be the same device ($efi_part)"
    exit 1
fi
if [[ "$use_snap_part" = "yes" ]]; then
    if [[ "$snap_part" = "$efi_part" || "$snap_part" = "$root_part" ]]; then
        show_error "Snapshot partition must be different from EFI ($efi_part) and root ($root_part)"
        exit 1
    fi
fi

####################################################################################################
# Format EFI partition
####################################################################################################

show_info "Formatting EFI partition"
mkfs.fat -n EFI -F 32 "$efi_part"

####################################################################################################
# Format root partition
####################################################################################################

show_info "Formatting root partition"

if cryptsetup isLuks "$root_part"; then
    show_info "LUKS header found - removing header"
    cryptsetup erase "$root_part"
else
    show_info "No LUKS header found"
fi

wipefs --all "$root_part" 2> /dev/null

if [ "$encrypt_root" = "yes" ]; then
    show_info "Creating LUKS container for the root partition"
    echo -n "$userpass" | cryptsetup -c aes-xts-plain64 -s 512 -h sha512 luksFormat "$root_part" -d - &>/dev/null
    echo -n "$userpass" | cryptsetup open "$root_part" cryptroot -d -
    DEVICE="/dev/mapper/cryptroot"
else
    DEVICE="$root_part"
fi

mkfs.ext4 -L "linux" "$DEVICE"

ESP="$efi_part"
ROOT="$root_part"

####################################################################################################
# Mount partitions
####################################################################################################

show_info "Mounting root and EFI partitions"

mount "$DEVICE" /mnt

mkdir -p /mnt/efi
mkdir -p /mnt/.snapshots

mount -o fmask=0137,dmask=0027 "$ESP" /mnt/efi

if [ "$use_snap_part" = "yes" ]; then
    show_info "Formatting and mounting snapshot partition"
    wipefs --all "$snap_part" 2> /dev/null
    mkfs.ext4 -L "snapshots" "$snap_part"
    mount "$snap_part" /mnt/.snapshots
fi

####################################################################################################
# Pacstrap
####################################################################################################

microcode_detector

show_info "Installing the base system (pacstrap) - this may take a while"
pacstrap -K /mnt base base-devel linux linux-headers linux-lts linux-lts-headers "$microcode" linux-firmware dosfstools cryptsetup nftables openssh tpm2-tools libfido2 pam-u2f pcsclite pcsc-tools audit man-db efitools efibootmgr reflector zram-generator sudo bash-completion curl wget git rsync stow restic rclone age gocryptfs fuse2 fuse3 vim jq fwupd usbguard >/dev/null
show_info "Base system installed"

####################################################################################################
# Generate /etc/fstab
####################################################################################################

show_info "Generating fstab"
genfstab -U /mnt > /mnt/etc/fstab

####################################################################################################
# Hostname
####################################################################################################

show_info "Setting hostname"
echo "$hostname" > /mnt/etc/hostname

####################################################################################################
# Locale
####################################################################################################

show_info "Setting locale"
locale="en_US.UTF-8"
sed -i "/^#$locale/s/^#//" /mnt/etc/locale.gen
echo "LANG=$locale" > /mnt/etc/locale.conf

####################################################################################################
# Console keymap
####################################################################################################

show_info "Setting keyboard layout"
echo "KEYMAP=$kblayout" > /mnt/etc/vconsole.conf

####################################################################################################
# Hosts file
####################################################################################################

show_info "Setting hosts file"
cat > /mnt/etc/hosts <<EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $hostname.localdomain   $hostname
EOF

####################################################################################################
# Network
####################################################################################################

show_info "Configuring network utilities"
network_installer

####################################################################################################
# Inform kernel of disk changes
####################################################################################################

show_info "Informing the kernel about disk changes"
partprobe &> /dev/null
sleep 2

show_info "Getting ROOT_UUID"
ROOT_UUID=$(blkid -s UUID -o value "$ROOT")
show_info "ROOT_UUID: $ROOT_UUID"

####################################################################################################
# Configure mkinitcpio
####################################################################################################

mkdir -p /mnt/boot
mkdir -p /mnt/efi/EFI/Linux
mkdir -p /mnt/etc/cmdline.d
mkdir -p /mnt/etc/mkinitcpio.d

show_info "Configuring AppArmor"
apparmor_installer

show_info "Configuring IOMMU hardening"
CPU=$(grep -m1 vendor_id /proc/cpuinfo)
if [[ "$CPU" == *"AuthenticAMD"* ]]; then
    cat > /mnt/etc/cmdline.d/iommu.conf <<EOF
# DMA protection: force IOMMU, disable passthrough
iommu=force iommu.passthrough=0
EOF
else
    cat > /mnt/etc/cmdline.d/iommu.conf <<EOF
# DMA protection: force IOMMU, disable passthrough
iommu=force iommu.passthrough=0 intel_iommu=on
EOF
fi

if [ "$use_lockdown" = "yes" ]; then
    show_info "Configuring kernel lockdown (integrity mode)"
    cat > /mnt/etc/cmdline.d/lockdown.conf <<EOF
# Kernel lockdown: prevent modification of the running kernel
lockdown=integrity
EOF
fi

show_info "Configuring kernel hardening arguments"
cat > /mnt/etc/cmdline.d/hardening.conf <<EOF
# Memory hardening: zero allocations/frees, randomize page allocator, disable slab merging
init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 slab_nomerge randomize_kstack_offset=on
# CPU vulnerability mitigations
pti=on spectre_v2=on spec_store_bypass_disable=on l1tf=full,force l1d_flush=on mitigations=auto
# Disable legacy attack surfaces
vsyscall=none vdso32=0
# Kernel pointer and entropy hardening
hash_pointers=always random.trust_bootloader=off random.trust_cpu=off
# IOMMU strict TLB invalidation
iommu.strict=1
# Disable initramfs debug shell
rd.shell=0 rd.emergency=halt
EOF

show_info "Configuring mkinitcpio"

if [ "$encrypt_root" = "yes" ]; then

    if [ "$unlock_method" = "tpm2" ]; then
        echo "cryptroot  UUID=$ROOT_UUID  none  tpm2-device=auto,password-echo=no,x-systemd.device-timeout=0,timeout=0,no-read-workqueue,no-write-workqueue"  >>  /mnt/etc/crypttab.initramfs
    elif [ "$unlock_method" = "fido2" ]; then
        echo "cryptroot  UUID=$ROOT_UUID  none  fido2-device=auto,password-echo=no,x-systemd.device-timeout=30,timeout=0,no-read-workqueue,no-write-workqueue"  >>  /mnt/etc/crypttab.initramfs
    else
        echo "cryptroot  UUID=$ROOT_UUID  none  password-echo=no,x-systemd.device-timeout=0,timeout=0,no-read-workqueue,no-write-workqueue"  >>  /mnt/etc/crypttab.initramfs
    fi

    echo "root=/dev/mapper/cryptroot rw quiet nowatchdog bgrt_disable zswap.enabled=0" >> /mnt/etc/cmdline.d/root.conf

cat > /mnt/etc/mkinitcpio.conf <<EOF
MODULES=(usbhid xhci_hcd hid-generic)
FILES=()
HOOKS=(base systemd keyboard autodetect microcode modconf kms sd-vconsole block sd-encrypt filesystems fsck)
EOF
else
    echo "root=UUID=$ROOT_UUID rw quiet nowatchdog bgrt_disable zswap.enabled=0" >> /mnt/etc/cmdline.d/root.conf

cat > /mnt/etc/mkinitcpio.conf <<EOF
MODULES=(usbhid xhci_hcd hid-generic)
FILES=()
HOOKS=(base systemd keyboard autodetect microcode modconf kms sd-vconsole block filesystems fsck)
EOF
fi

cat > /mnt/etc/mkinitcpio.d/linux.preset <<EOF
# mkinitcpio preset file to generate UKIs

ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default')

default_uki="/efi/EFI/Linux/arch-linux.efi"
default_options="--splash=/usr/share/systemd/bootctl/splash-arch.bmp"
EOF

cat > /mnt/etc/mkinitcpio.d/linux-lts.preset <<EOF
# mkinitcpio preset file to generate UKIs

ALL_kver="/boot/vmlinuz-linux-lts"

PRESETS=('default')

default_uki="/efi/EFI/Linux/arch-linux-lts.efi"
default_options="--splash=/usr/share/systemd/bootctl/splash-arch.bmp"
EOF

####################################################################################################
# arch-chroot: timezone, clock, locale, mkinitcpio
####################################################################################################

show_info "Configuring the system (arch-chroot: timezone, clock, initramfs)"

arch-chroot /mnt /bin/bash -e <<EOF

    # Setting up timezone.
    ln -sf /usr/share/zoneinfo/$timezone /etc/localtime &>/dev/null

    # Setting up clock.
    hwclock --systohc

    # Generating locales.
    locale-gen &>/dev/null

    # Generating a new initramfs.
    mkinitcpio -P

EOF

####################################################################################################
# EFISTUB boot entries
####################################################################################################

show_info "Managing EFI boot entries"

efibootmgr --unicode

# Delete existing boot entries
while true; do
    entries=$(efibootmgr --unicode 2>/dev/null | grep "^Boot[0-9]" || true)

    if [[ -z "$entries" ]]; then
        show_info "No boot entries found"
        break
    fi

    entry=$(echo -e "Skip\n$entries" | gum choose --header "Select boot entry to delete (or Skip):")

    if [[ "$entry" = "Skip" ]]; then
        break
    fi

    boot_num=$(echo "$entry" | grep -oP 'Boot\K[0-9A-Fa-f]{4}')
    if [[ -n "$boot_num" ]]; then
        efibootmgr --bootnum "$boot_num" --delete-bootnum --unicode
        show_info "Deleted boot entry $boot_num"
    fi
done

show_info "Building EFISTUB entries"

efi_dev=$(lsblk --noheadings --raw --output PKNAME "$ESP")
efi_part_num=$(echo "$ESP" | grep -Eo '[0-9]+$')

arch-chroot /mnt efibootmgr --create --disk /dev/"${efi_dev}" --part "${efi_part_num}" --label "arch-linux-lts" --loader "EFI\Linux\arch-linux-lts.efi" --unicode
arch-chroot /mnt efibootmgr --create --disk /dev/"${efi_dev}" --part "${efi_part_num}" --label "arch-linux" --loader "EFI\Linux\arch-linux.efi" --unicode

####################################################################################################
# Final configurations
####################################################################################################

show_info "Configuring sysctl"
set_sysctl

show_info "Configuring modprobe"
set_modprobe

show_info "Disabling core dumps"
set_coredump

show_info "Configuring systemd-resolved"
set_systemd_resolved

show_info "Configuring ZRAM"
cat > /mnt/etc/systemd/zram-generator.conf <<EOF
[zram0]
zram-size = min(ram / 2, 4 * 1024)
compression-algorithm = zstd
EOF

####################################################################################################
# Disable suspend and hibernate
####################################################################################################

show_info "Masking sleep-related systemd targets"
systemctl mask suspend.target --root=/mnt &>/dev/null
systemctl mask hibernate.target --root=/mnt &>/dev/null
systemctl mask hybrid-sleep.target --root=/mnt &>/dev/null
systemctl mask suspend-then-hibernate.target --root=/mnt &>/dev/null

show_info "Configuring logind to ignore sleep events"
mkdir -p /mnt/etc/systemd/logind.conf.d
cat > /mnt/etc/systemd/logind.conf.d/no-sleep.conf <<EOF
[Login]
HandleLidSwitch=lock
HandleLidSwitchExternalPower=lock
HandleLidSwitchDocked=ignore
HandlePowerKey=poweroff
HandleSuspendKey=ignore
HandleHibernateKey=ignore
IdleAction=ignore
EOF

show_info "Disabling sleep at the systemd-sleep level"
mkdir -p /mnt/etc/systemd/sleep.conf.d
cat > /mnt/etc/systemd/sleep.conf.d/no-sleep.conf <<EOF
[Sleep]
AllowSuspend=no
AllowHibernation=no
AllowSuspendThenHibernate=no
AllowHybridSleep=no
EOF

show_info "Configuring pacman: colors, animations, parallel downloads"
sed -Ei 's/^#(Color)$/\1\nILoveCandy/;s/^#(ParallelDownloads).*/\1 = 10/' /mnt/etc/pacman.conf

show_info "Configuring reflector"
mkdir -p /mnt/etc/xdg/reflector
cat > /mnt/etc/xdg/reflector/reflector.conf <<EOF
--save /etc/pacman.d/mirrorlist
--country '$reflector_country'
--protocol https
--latest 5
EOF

####################################################################################################
# Enable services
####################################################################################################

show_info "Enabling systemd-timesyncd"
systemctl enable systemd-timesyncd --root=/mnt &>/dev/null

show_info "Enabling polkit"
systemctl enable polkit.service --root=/mnt &>/dev/null

show_info "Deploying polkit rules"
mkdir -p /mnt/etc/polkit-1/rules.d
cp /root/tent/settings/polkit/00-udisks-wheel.rules /mnt/etc/polkit-1/rules.d/00-udisks-wheel.rules

####################################################################################################
# Add user
####################################################################################################

show_info "Creating user $username"
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /mnt/etc/sudoers.d/wheel
arch-chroot /mnt chmod 0440 /etc/sudoers.d/wheel
show_info "Adding $username to the system with root privilege"
arch-chroot /mnt useradd -m -G users,wheel -s /bin/bash "$username"
show_info "Setting user password for $username"
echo "$username:$userpass" | arch-chroot /mnt chpasswd
unset userpass userpass2

####################################################################################################
# Install paru
####################################################################################################

show_info "Installing paru"

arch-chroot /mnt runuser -u "$username" -- bash -c '
    cd ~
    git clone https://aur.archlinux.org/paru-bin.git >/dev/null
    cd paru-bin
    makepkg -si --noconfirm >/dev/null
    cd ~
    rm -rf paru-bin
'

# Remove NOPASSWD privileges
rm /mnt/etc/sudoers.d/wheel
echo "%wheel ALL=(ALL:ALL) ALL" > /mnt/etc/sudoers.d/wheel
arch-chroot /mnt chmod 0440 /etc/sudoers.d/wheel

####################################################################################################
# run0 hardening (replace sudo, strip SUID/SGID, apply capabilities)
####################################################################################################

if [ "$use_run0" = "yes" ]; then
    show_info "Configuring run0 as sudo replacement"
    set_run0
fi

####################################################################################################
# Restic configuration
####################################################################################################

show_info "creating restic cache directory"
mkdir -p /mnt/var/cache/restic

####################################################################################################
# Lock root account
####################################################################################################

show_info "Locking root account"
arch-chroot /mnt passwd -l root &>/dev/null

####################################################################################################
# LUKS key enrollment (TPM2 or FIDO2)
####################################################################################################

if [ "$unlock_method" = "tpm2" ]; then
    show_info "Enrolling TPM2 LUKS key with PIN: the password to unlock the root volume is your user password"
    systemd-cryptenroll "$ROOT" --tpm2-device=auto --tpm2-with-pin=yes
    show_info "Enrolling recovery key"
    systemd-cryptenroll "$ROOT" --recovery-key
    show_info "Removing original password keyslot"
    systemd-cryptenroll "$ROOT" --wipe-slot=password
elif [ "$unlock_method" = "fido2" ]; then
    gum style --foreground 212 --bold --margin "1 0" "FIDO2 Enrollment"
    gum style --foreground 214 --margin "0 2" \
        "Insert your primary FIDO2 key and press Enter to continue."
    gum confirm "Primary FIDO2 key is inserted?" || { show_error "FIDO2 enrollment cancelled"; exit 1; }
    show_info "Enrolling primary FIDO2 key with PIN"
    systemd-cryptenroll "$ROOT" --fido2-device=auto --fido2-with-client-pin=yes --fido2-credential-algorithm=eddsa

    if [ "$fido2_backup" = "yes" ]; then
        gum style --foreground 214 --margin "1 2" \
            "Remove the primary FIDO2 key." \
            "Insert your backup FIDO2 key and press Enter to continue."
        gum confirm "Backup FIDO2 key is inserted?" || { show_error "Backup FIDO2 key enrollment cancelled"; exit 1; }
        show_info "Enrolling backup FIDO2 key with PIN"
        systemd-cryptenroll "$ROOT" --fido2-device=auto --fido2-with-client-pin=yes --fido2-credential-algorithm=eddsa
    fi

    show_info "Enrolling recovery key"
    systemd-cryptenroll "$ROOT" --recovery-key
    show_info "Removing original password keyslot"
    systemd-cryptenroll "$ROOT" --wipe-slot=password
fi

####################################################################################################
# Secure Boot
####################################################################################################

if [ "$secure_boot" = "yes" ]; then
    show_info "Installing sbctl"
    pacstrap /mnt sbctl &>/dev/null

    arch-chroot /mnt /bin/bash -e <<EOF
if sbctl status | grep -q 'Setup Mode:.*Enabled'; then
  echo "Secure Boot is in setup mode, proceeding with secure boot configuration"
  sbctl create-keys
  sbctl enroll-keys -m
  sbctl sign -s /efi/EFI/Linux/arch-linux.efi
  sbctl sign -s /efi/EFI/Linux/arch-linux-lts.efi
  sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi

  sbctl verify
  sbctl status
else
  echo "Secure Boot is not in setup mode, aborting"
  exit 1
fi
EOF

    # Re-install kernel to trigger sbctl pacman hook to sign UKIs
    show_info "Re-installing kernels to sign with Secure Boot keys"
    pacstrap /mnt linux linux-lts
fi

####################################################################################################
# Final message
####################################################################################################

echo ""

if [ "$encrypt_root" = "yes" ]; then
    case "$unlock_method" in
        tpm2)
            show_info "Root partition is encrypted (LUKS) with TPM2 + PIN. A recovery key has also been enrolled."
            show_info "Use systemd-cryptenroll to manage enrollment slots."
            ;;
        fido2)
            if [ "$fido2_backup" = "yes" ]; then
                show_info "Root partition is encrypted (LUKS) with two FIDO2 keys + PIN. A recovery key has also been enrolled."
            else
                show_info "Root partition is encrypted (LUKS) with FIDO2 + PIN. A recovery key has also been enrolled."
            fi
            show_info "If no FIDO2 key is present at boot, the system will wait 30 seconds then fall back to a passphrase prompt (use the recovery key)."
            show_info "Use systemd-cryptenroll to manage enrollment slots."
            ;;
        passphrase)
            show_info "Root partition is encrypted (LUKS) with user password. Use systemd-cryptenroll to enroll TPM2, FIDO2, or change the password."
            ;;
    esac
fi

show_info "USBGuard is installed but NOT enabled."
show_info "After first boot, plug in all trusted USB devices, then run:"
show_info "  sudo usbguard generate-policy > /etc/usbguard/rules.conf"
show_info "  sudo systemctl enable --now usbguard"
show_info "Add your username to IPCAllowedUsers in /etc/usbguard/usbguard-daemon.conf for non-root CLI access."

if [ "$use_run0" = "yes" ]; then
    echo ""
    show_info "run0 is active. sudo calls are transparently redirected to run0."
    show_info "SUID/SGID bits have been stripped (whitelist model). Capabilities applied."
    show_info "The pacman hook /etc/pacman.d/hooks/99-harden-suid.hook maintains this state."
    show_info "To whitelist a new SUID binary: edit /usr/local/bin/harden-suid"
fi

gum style \
    --foreground 82 --border-foreground 82 --border double \
    --align center --width 70 --margin "1 2" --padding "1 2" \
    "Installation Complete" \
    "" \
    "Reboot into firmware and enable Secure Boot:" \
    "systemctl reboot --firmware-setup"

exit

####################################################################################################
# end
####################################################################################################
