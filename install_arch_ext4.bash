#!/usr/bin/env -S bash -e

clear

######################################################
# Cosmetics (colours for text).
######################################################
BOLD='\e[1m'
BRED='\e[91m'
BBLUE='\e[34m'  
BGREEN='\e[92m'
BYELLOW='\e[93m'
RESET='\e[0m'

######################################################
# Pretty print (function).
######################################################
info_print () {
    echo -e "${BOLD}${BGREEN}[ ${BYELLOW}•${BGREEN} ] $1${RESET}"
}

######################################################
# Pretty print for input (function).
######################################################
input_print () {
    echo -ne "${BOLD}${BYELLOW}[ ${BGREEN}•${BYELLOW} ] $1${RESET}"
}

######################################################
# Alert user of bad input (function).
######################################################
error_print () {
    echo -e "${BOLD}${BRED}[ ${BBLUE}•${BRED} ] $1${RESET}"
}

######################################################
# apparmor
######################################################
ask_apparmor () {

    info_print "apparmor"
    read -r -p "Do you want to enable apparmor? (yes/no): " use_apparmor
    
    use_apparmor=$(echo "$use_apparmor" | tr '[:upper:]' '[:lower:]')
    
    case "$use_apparmor" in
        yes|no)
            return 0
            ;;
        *)
            echo "Invalid response. Please answer 'yes' or 'no'." >&2
            return 1
            ;;
    esac
}

######################################################
# apparmor
######################################################
apparmor_installer () {

if [ "$use_apparmor" = "yes" ]; then
cat > /mnt/etc/cmdline.d/security.conf <<EOF
# enable apparmor
lsm=landlock,lockdown,yama,integrity,apparmor,bpf audit=1 audit_backlog_limit=256
EOF

systemctl enable apparmor.service --root=/mnt &>/dev/null
systemctl enable auditd.service --root=/mnt &>/dev/null
else
cat > /mnt/etc/cmdline.d/security.conf <<EOF
# enable apparmor
# lsm=landlock,lockdown,yama,integrity,apparmor,bpf audit=1 audit_backlog_limit=256
EOF
fi

echo "write-cache" >> /mnt/etc/apparmor/parser.conf
echo "Optimize=compress-fast" >> /mnt/etc/apparmor/parser.conf
}

######################################################
# firewalld
######################################################
ask_firewalld () {

    read -r -p "Do you want to install and enable firewalld? (yes/no): " use_firewalld
    
    use_firewalld=$(echo "$use_firewalld" | tr '[:upper:]' '[:lower:]')
    
    case "$use_firewalld" in
        yes|no)
            return 0
            ;;
        *)
            echo "Invalid response. Please answer 'yes' or 'no'." >&2
            return 1
            ;;
    esac
}

######################################################
# firewalld
######################################################
firewalld_installer () {

    if [ "$use_firewalld" = "yes" ]; then
        info_print "installing and configuring firewalld"
        pacstrap /mnt firewalld &>/dev/null
        systemctl enable firewalld.service --root=/mnt &>/dev/null
        arch-chroot /mnt firewall-offline-cmd --set-default-zone=drop
    fi
}

######################################################
# luks encryption 
######################################################
ask_encrypt_root () {

    info_print "luks encryption"
    read -r -p "Do you want to encrypt the root partition? (yes/no): " encrypt_root
    
    encrypt_root=$(echo "$encrypt_root" | tr '[:upper:]' '[:lower:]')
    
    case "$encrypt_root" in
        yes|no)
            return 0
            ;;
        *)
            echo "Invalid response. Please answer 'yes' or 'no'." >&2
            return 1
            ;;
    esac
}

######################################################
# luks encryption: fido2 key
######################################################
ask_encrypt_key () {

    info_print "luks encryption"
    read -r -p "Do you want to enroll a fido2 luks key? (yes/no): " encrypt_key
    
    encrypt_key=$(echo "$encrypt_key" | tr '[:upper:]' '[:lower:]')
    
    case "$encrypt_key" in
        yes|no)
            return 0
            ;;
        *)
            echo "Invalid response. Please answer 'yes' or 'no'." >&2
            return 1
            ;;
    esac
}

######################################################
# sbctl
######################################################
ask_secure_boot () {

    info_print "secure boot"
    read -r -p "Do you want to enable secure boot? (yes/no): " secure_boot
    
    secure_boot=$(echo "$encrypt_root" | tr '[:upper:]' '[:lower:]')
    
    case "$secure_boot" in
        yes|no)
            return 0
            ;;
        *)
            echo "Invalid response. Please answer 'yes' or 'no'." >&2
            return 1
            ;;
    esac
}

######################################################
# user password
######################################################
userpass_selector () {
    input_print "Please enter name for user account: "
    read -r username
    if [[ -z "$username" ]]; then
        error_print "You need to enter a user name"
        return 1
    fi
    input_print "Please enter a password for $username (you're not going to see the password): "
    read -r -s userpass
    if [[ -z "$userpass" ]]; then
        echo
        error_print "You need to enter a password for $username, please try again."
        return 1
    fi
    echo
    input_print "Please enter the password again (you're not going to see it): " 
    read -r -s userpass2
    echo
    if [[ "$userpass" != "$userpass2" ]]; then
        echo
        error_print "Passwords don't match, please try again."
        return 1
    fi
    return 0
}

######################################################
# snapshot partition
######################################################
ask_snap_part () {

    info_print "snapshot partition"
    read -r -p "Do you want to mount a snapshot partition? (yes/no): " use_snap_part
    
    use_snap_part=$(echo "$use_snap_part" | tr '[:upper:]' '[:lower:]')
    
    case "$use_snap_part" in
        yes|no)
            return 0
            ;;
        *)
            echo "Invalid response. Please answer 'yes' or 'no'." >&2
            return 1
            ;;
    esac
}

######################################################
# network selection
######################################################
network_selector () {
    info_print "Network utilities:"
    info_print "1) iwd + systemd-networkd"
    info_print "2) systemd-networkd only"
    info_print "3) NetworkManager"
    input_print "Please select the number of the corresponding networking utility (e.g. 1): "
    read -r network_choice
    if ! ((1 <= network_choice <= 3)); then
        error_print "You did not enter a valid selection, please try again."
        return 1
    fi
    return 0
}

######################################################
# network selection
######################################################
network_installer () {
    case $network_choice in
        1 ) info_print "enabling systemd-networkd, installing and enabling iwd."
            pacstrap /mnt iwd >/dev/null
            systemctl enable systemd-networkd.service --root=/mnt &>/dev/null
            systemctl enable iwd.service --root=/mnt &>/dev/null
            set_systemd_networkd
            set_iwd
            ;;
        2 ) info_print "enabling systemd-networkd"
            systemctl enable systemd-networkd.service --root=/mnt &>/dev/null
            set_systemd_networkd
            ;;
        3 ) info_print "Installing and enabling NetworkManager."
            pacstrap /mnt networkmanager network-manager-applet nm-connection-editor >/dev/null
            cp /root/install-arch/settings/network/NetworkManager.conf /mnt/etc/NetworkManager/NetworkManager.conf
            systemctl enable NetworkManager.service --root=/mnt &>/dev/null
    esac
}

######################################################
# microcode
######################################################
microcode_detector () {
    CPU=$(grep vendor_id /proc/cpuinfo)
    if [[ "$CPU" == *"AuthenticAMD"* ]]; then
        info_print "An AMD CPU has been detected, the AMD microcode will be installed."
        microcode="amd-ucode"
    else
        info_print "An Intel CPU has been detected, the Intel microcode will be installed."
        microcode="intel-ucode"
    fi
}

######################################################
# hostname
######################################################
hostname_selector () {
    input_print "Please enter the hostname: "
    read -r hostname
    if [[ -z "$hostname" ]]; then
        error_print "You need to enter a hostname in order to continue."
        return 1
    fi
    return 0
}

######################################################
# settings
######################################################
set_sysctl() {
cp /root/install-arch/settings/sysctl/99-firewall-settings.conf /mnt/etc/sysctl.d/99-firewall-settings.conf 
cp /root/install-arch/settings/sysctl/99-watchdog-settings.conf /mnt/etc/sysctl.d/99-watchdog-settings.conf 
cp /root/install-arch/settings/sysctl/99-zram-settings.conf /mnt/etc/sysctl.d/99-zram-settings.conf
}

set_modprobe() {
cp /root/install-arch/settings/modprobe/blacklist.conf /mnt/etc/modprobe.d/blacklist.conf
cp /root/install-arch/settings/modprobe/disable-firewire.conf /mnt/etc/modprobe.d/disable-firewire.conf
cp /root/install-arch/settings/modprobe/iwlwifi.conf /mnt/etc/modprobe.d/iwlwifi.conf
}

set_systemd_networkd() {
mkdir /mnt/etc/systemd/system/systemd-networkd-wait-online.service.d
cp /root/install-arch/settings/network/20-wired.network /mnt/etc/systemd/network/20-wired.network 
cp /root/install-arch/settings/network/wait-for-only-one-interface.conf /mnt/etc/systemd/system/systemd-networkd-wait-online.service.d/wait-for-only-one-interface.conf
sed -i '/^#ManageForeignRoutingPolicyRules=yes/c\ManageForeignRoutingPolicyRules=no' /mnt/etc/systemd/networkd.conf
}

set_iwd() {
mkdir /mnt/etc/iwd
mkdir /mnt/etc/systemd/system/iwd.service.d
cp /root/install-arch/settings/network/25-wireless.network /mnt/etc/systemd/network/25-wireless.network 
cp /root/install-arch/settings/network/iwd.main.conf /mnt/etc/iwd/main.conf 
cp /root/install-arch/settings/network/iwd.override.conf /mnt/etc/systemd/system/iwd.service.d/override.conf 
cp -r /var/lib/iwd /mnt/var/lib
}

set_systemd_resolved() {
ln -sf /run/systemd/resolve/stub-resolv.conf /mnt/etc/resolv.conf
cp /root/install-arch/settings/network/resolved.conf /mnt/etc/systemd/resolved.conf 
systemctl enable systemd-resolved --root=/mnt &>/dev/null
}

######################################################
# Begin Instalation
######################################################
echo -ne "${BOLD}${BYELLOW}
======================================================================

   / \   _ __ ___| |__   | |   (_)_ __  _   ___  __
  / _ \ | '__/ __| '_ \  | |   | | '_ \| | | \ \/ /
 / ___ \| | | (__| | | | | |___| | | | | |_| |>  <
/_/   \_\_|  \___|_| |_| |_____|_|_| |_|\__,_/_/\_\

======================================================================

${RESET}"
info_print "Arch Linux installation script beginning:"

info_print "updating arch-keyring and syncronizing clock"
timedatectl set-ntp true
pacman -Sy --noconfirm archlinux-keyring >/dev/null

kblayout="us"
info_print "setting console layout to $kblayout."
loadkeys "$kblayout"

####################################################################################################
# Luks
####################################################################################################
until ask_encrypt_root; do : ; done

if [ "$encrypt_root" = "yes" ]; then
    until ask_encrypt_key; do : ; done
else
    encrypt_key="no"
fi

####################################################################################################
# Secure Boot
####################################################################################################
until ask_secure_boot; do : ; done

####################################################################################################
# Setting up the kernel.
####################################################################################################
until ask_apparmor; do : ; done

####################################################################################################
# User choses the network.
####################################################################################################
until network_selector; do : ; done

####################################################################################################
# firewalld
####################################################################################################
until ask_firewalld; do : ; done

####################################################################################################
# User choses the hostname.
####################################################################################################
until hostname_selector; do : ; done

####################################################################################################
# User sets up the user/root passwords.
####################################################################################################
until userpass_selector; do : ; done

####################################################################################################
# wipe disk
####################################################################################################
info_print 'Secure Wipe Disks'

devices=$(lsblk --nodeps --paths --list --noheadings --sort=size --output=name,size,model | grep --invert-match "loop" | cat --number)

device_id=" "
while [[ -n $device_id ]]; do
    echo -e "Choose device to securly wipe:"
    echo "$devices"
    read -r -p "Enter a number (empty to skip): " device_id
    if [[ -n $device_id ]] ; then
        device=$(echo "$devices" | awk "\$1 == $device_id { print \$2}")
        wipefs --all "$device"
        cryptsetup open --type plain -c aes-xts-plain64 -d /dev/urandom "$device" to_be_wiped
        dd if=/dev/zero of=/dev/mapper/to_be_wiped bs=1M status=progress || true
        cryptsetup close /dev/mapper/to_be_wiped
        echo "secure wipe is complete"
    fi
done

####################################################################################################
# partition disks
####################################################################################################
info_print 'Partition Disks'

devices=$(lsblk --nodeps --paths --list --noheadings --sort=size --output=name,size,model | grep --invert-match "loop" | cat --number)

device_id=" "
while [[ -n $device_id ]]; do
    echo -e "Choose device to format:"
    echo "$devices"
    read -r -p "Enter a number (empty to skip): " device_id
    if [[ -n $device_id ]] ; then
        device=$(echo "$devices" | awk "\$1 == $device_id { print \$2}")
        fdisk "$device"
    fi
done

partitions=$(lsblk --paths --list --noheadings --output=name,size,model | grep --invert-match "loop" | cat --number)

# EFI partition
echo -e "\n\nTell me the EFI partition number:"
echo "$partitions"
read -r -p "Enter a number: " efi_id
efi_part=$(echo "$partitions" | awk "\$1 == $efi_id { print \$2}")

# root partition
echo -e "\n\nTell me the root partition number:"
echo "$partitions"
read -r -p "Enter a number: " root_id
root_part=$(echo "$partitions" | awk "\$1 == $root_id { print \$2}")

# snapshot partition
until ask_snap_part; do : ; done

if [ "$use_snap_part" = "yes" ]; then
    echo -e "\n\nTell me the snapshot partition number:"
    echo "$partitions"
    read -r -p "Enter a number: " root_id
    snap_part=$(echo "$partitions" | awk "\$1 == $root_id { print \$2}")
fi

####################################################################################################
# Formating the efi partition.
####################################################################################################

info_print 'Formatting EFI Partition'

mkfs.fat -n EFI -F 32 "$efi_part"

####################################################################################################
# Formating the root partition.
####################################################################################################

info_print 'Formatting Root Partition'

if cryptsetup isLuks "$root_part"; then
    info_print 'LUKS header found - removing header'
    cryptsetup erase "$root_part"
else
    info_print 'No LUKS header found'
fi

wipefs --all "$root_part" 2> /dev/null

if [ "$encrypt_root" = "yes" ]; then
    info_print "Creating LUKS Container for the root partition."
    echo -n "$userpass" | cryptsetup -c serpent-xts-plain64 -s 512 -h sha512 luksFormat "$root_part" -d - &>/dev/null
    echo -n "$userpass" | cryptsetup open "$root_part" cryptroot -d - 
    DEVICE="/dev/mapper/cryptroot"
else
    DEVICE="$root_part"
fi

mkfs.ext4 -L "linux" "$DEVICE"

ESP="$efi_part"
ROOT="$root_part"

####################################################################################################
# mounting partitions
####################################################################################################

info_print "mounting root and efi partitions"

mount "$DEVICE" /mnt

mkdir /mnt/efi
mkdir /mnt/.snapshots

mount -o fmask=0137,dmask=0027 "$ESP" /mnt/efi

if [ "$use_snap_part" = "yes" ]; then
    info_print "formating and mounting snapshots partition"
    wipefs --all "$snap_part" 2> /dev/null
    mkfs.ext4 -L "snapshots" "$snap_part"
    mount "$snap_part" /mnt/.snapshots
fi

####################################################################################################
# Pacstrap (setting up a base system onto the new root).
####################################################################################################

microcode_detector

info_print "Installing the base system (pacstrap)"
pacstrap -K /mnt base base-devel linux linux-headers linux-lts linux-lts-headers "$microcode" linux-firmware apparmor openssh tpm2-tools libfido2 pam-u2f pcsclite man-db efitools efibootmgr reflector zram-generator sudo bash-completion curl wget git rsync stow neovim tldr jq restic &>/dev/null

####################################################################################################
# Generating /etc/fstab.
####################################################################################################

info_print "Generating a new fstab"
genfstab -U /mnt >> /mnt/etc/fstab

####################################################################################################
# Setting up the hostname.
####################################################################################################
info_print "setting hostname"

echo "$hostname" > /mnt/etc/hostname

####################################################################################################
#  set locale
####################################################################################################
info_print "setting locale"

locale="en_US.UTF-8"

sed -i "/^#$locale/s/^#//" /mnt/etc/locale.gen
echo "LANG=$locale" > /mnt/etc/locale.conf

####################################################################################################
#  set console keymap
####################################################################################################
info_print "setting keyboard layout"

echo "KEYMAP=$kblayout" > /mnt/etc/vconsole.conf

####################################################################################################
# Setting hosts file.
####################################################################################################
info_print "setting hosts file."

cat > /mnt/etc/hosts <<EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $hostname.localdomain   $hostname
EOF

####################################################################################################
# Setting up the network.
####################################################################################################

info_print "configure network utilities"
network_installer

####################################################################################################
# Informing the Kernel of the changes.
####################################################################################################

info_print "Informing the Kernel about the disk changes."
partprobe &> /dev/null
sleep 2

info_print "getting ROOT_UUID"
echo "ROOT = :"
echo "$ROOT"
ROOT_UUID=$(blkid -s UUID -o value $ROOT)

####################################################################################################
# configure mkinitcpio
####################################################################################################

mkdir -p /mnt/boot
mkdir -p /mnt/efi/EFI/Linux
mkdir -p /mnt/etc/cmdline.d
mkdir -p /mnt/etc/mkinitcpio.d

info_print "Configuring apparmor"
apparmor_installer

info_print "Configuring mkinitcpio"

if [ "$encrypt_root" = "yes" ]; then

    if [ "$encrypt_key" = "yes" ]; then
        echo "cryptroot  UUID=$ROOT_UUID  none  fido2-device=auto,password-echo=no,x-systemd.device-timeout=0,timeout=0,no-read-workqueue,no-write-workqueue"  >>  /mnt/etc/crypttab.initramfs
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
# arch-chroot - timezone, clock, locale, mkinitcpio
####################################################################################################

info_print "Configuring the system (arch-chroot - timezone, system clock, initramfs)"

arch-chroot /mnt /bin/bash -e <<EOF

    # Setting up timezone.
    ln -sf /usr/share/zoneinfo/US/Eastern /etc/localtime &>/dev/null

    # Setting up clock.
    hwclock --systohc

    # Generating locales.
    locale-gen &>/dev/null

    # Generating a new initramfs.
    # mkinitcpio -p &>/dev/null
    mkinitcpio -P

    # install systemd-boot
    # uncomment this if you want to use systemd-boot 
    # bootctl install --esp-path=/efi
EOF

####################################################################################################
# efistub boot
####################################################################################################

info_print "Delete Boot Entries"

efibootmgr --unicode
efi_boot_id=" "
while [[ -n $efi_boot_id ]]; do
    input_print "Enter the boot number of the boot entry you would like to delete (empty to skip): "
    read -r efi_boot_id
    if [[ -n $efi_boot_id ]] ; then
        efibootmgr --bootnum "$efi_boot_id" --delete-bootnum --unicode
    fi
done

info_print "building efistub"

efi_dev=$(lsblk --noheadings --output PKNAME $ESP)
efi_part_num=$(echo $ESP | grep -Eo '[0-9]+$')

arch-chroot /mnt efibootmgr --create --disk /dev/"${efi_dev}" --part ${efi_part_num} --label "arch-linux" --loader "EFI\Linux\arch-linux.efi" --unicode
arch-chroot /mnt efibootmgr --create --disk /dev/"${efi_dev}" --part ${efi_part_num} --label "arch-linux-lts" --loader "EFI\Linux\arch-linux-lts.efi" --unicode

####################################################################################################
# final configurations
####################################################################################################

info_print 'configuring sysctl'
set_sysctl

info_print 'configuring modprobe'
set_modprobe

info_print 'configuring systemd-resolved'
set_systemd_resolved

info_print "configuring ZRAM."
cat > /mnt/etc/systemd/zram-generator.conf <<EOF
[zram0]
zram-size = min(ram / 2, 4 * 1024)
compression-algorithm = zstd
EOF

# firewalld
firewalld_installer

# Pacman eye-candy features.
info_print "configure pacman: enabling colors, animations, and parallel downloads"
sed -Ei 's/^#(Color)$/\1\nILoveCandy/;s/^#(ParallelDownloads).*/\1 = 10/' /mnt/etc/pacman.conf

# reflector
info_print "configure reflector"
cat > /mnt/etc/xdg/reflector/reflector.conf <<EOF
--save /etc/pacman.d/mirrorlist
--country 'United States'
--protocol https
--latest 5
EOF

####################################################################################################
# Enabling services
####################################################################################################
info_print "enabling services: systemd-timesyncd"
systemctl enable systemd-timesyncd --root=/mnt &>/dev/null

####################################################################################################
# Add user
####################################################################################################

info_print "creating user"
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /mnt/etc/sudoers.d/wheel
arch-chroot /mnt chmod 0440 /etc/sudoers.d/wheel
info_print "Adding the user $username to the system with root privilege."
arch-chroot /mnt useradd -m -G users,wheel -s /bin/bash "$username"
info_print "Setting user password for $username."
echo "$username:$userpass" | arch-chroot /mnt chpasswd

####################################################################################################
# install paru
####################################################################################################
info_print "installing paru"

arch-chroot /mnt /bin/bash -e <<EOF
su $username
cd ~/
git clone https://aur.archlinux.org/paru-bin.git &>/dev/null
cd paru-bin
makepkg -si --noconfirm >/dev/null
cd ~/
rm -rf paru-bin
exit
EOF

# remove NOPASSWD privileges
rm /mnt/etc/sudoers.d/wheel
echo "%wheel ALL=(ALL:ALL) ALL" > /mnt/etc/sudoers.d/wheel
arch-chroot /mnt chmod 0440 /etc/sudoers.d/wheel

####################################################################################################
# restic configurations
####################################################################################################

info_print "configuring restic"
mkdir -p /mnt/etc/restic
mkdir -p /mnt/etc/pacman.d/hooks
mkdir -p /mnt/etc/pacman.d/scripts
mkdir -p /mnt/var/cache/restic

cp /root/install-arch/settings/restic/env_file /mnt/etc/restic/env_file
cp /root/install-arch/settings/restic/exclude_file /mnt/etc/restic/exclude_file

cp /root/install-arch/settings/restic/hooks/05-system-snap-pre.hook /mnt/etc/pacman.d/hooks/05-system-snap-pre.hook
cp /root/install-arch/settings/restic/hooks/zzz-system-snap-post.hook /mnt/etc/pacman.d/hooks/zzz-system-snap-post.hook
cp /root/install-arch/settings/restic/scripts/restic-system-backup-auto /mnt/etc/pacman.d/scripts/restic-system-backup-auto
arch-chroot /mnt chmod +x /etc/pacman.d/scripts/restic-system-backup-auto

cp /root/install-arch/settings/restic/scripts/restic-init /mnt/usr/local/sbin/restic-init
cp /root/install-arch/settings/restic/scripts/restic-system /mnt/usr/local/sbin/restic-system
cp /root/install-arch/settings/restic/scripts/restic-system-backup /mnt/usr/local/sbin/restic-system-backup
cp /root/install-arch/settings/restic/scripts/restic-system-rollback /mnt/usr/local/sbin/restic-system-rollback

arch-chroot /mnt chmod +x /usr/local/sbin/restic-init
arch-chroot /mnt chmod +x /usr/local/sbin/restic-system
arch-chroot /mnt chmod +x /usr/local/sbin/restic-system-backup
arch-chroot /mnt chmod +x /usr/local/sbin/restic-system-rollback
arch-chroot /mnt chmod +x /etc/pacman.d/scripts/restic-system-backup-auto

info_print "initialize restic system repo"
arch-chroot /mnt /usr/local/sbin/restic-init

####################################################################################################
# lock root account
####################################################################################################

info_print "Locking root account"
arch-chroot /mnt passwd -d root &>/dev/null
arch-chroot /mnt passwd -l root &>/dev/null

####################################################################################################
# enroll key
####################################################################################################

if [ "$encrypt_key" = "yes" ]; then
    info_print "Enrolling fido2 luks key: please follow instructions"
    systemd-cryptenroll "$ROOT" --wipe-slot=all --fido2-device=auto --fido2-with-client-pin=yes --fido2-credential-algorithm=eddsa 
fi

####################################################################################################
# secure boot
####################################################################################################

if [ "$secure_boot" = "yes" ]; then
pacstrap /mnt sbctl &>/dev/null

arch-chroot /mnt /bin/bash -e <<EOF
if sbctl status | grep -q 'Setup Mode:.*Enabled'; then
  echo "Secure Boot is in setup mode, proceeding with secure boot configuration"
  sbctl create-keys
  sbctl enroll-keys -m
  sbctl sign -s /efi/EFI/Linux/arch-linux.efi
  sbctl sign -s /efi/EFI/Linux/arch-linux-lts.efi

  sbctl verify
  sbctl status
else
  echo "Secure Boot is not in setup mode, aborting"
fi
exit
EOF

# re-install kernel to make sure secureboot signs kernel
pacstrap /mnt linux linux-lts
fi

####################################################################################################
# final message
####################################################################################################

if [ "$encrypt_root" = "yes" ]; then
  if [ "$encrypt_key" = "yes" ]; then
      info_print "Root partion is encrypted (LUKS) with a single fido2 key. Use systemd-cryptenroll to enroll a backup password or recovery key"
  else
      info_print "Root partion is encrypted (LUKS) with user password. Use systemd-cryptenroll to change the password or to change the encryption method to fido2 or tpm"
  fi
fi

info_print "Success, reboot into firmware and enable secure boot"
exit

####################################################################################################
# end
####################################################################################################
