#!/usr/bin/env -S bash -e

clear

# Cosmetics (colours for text).
BOLD='\e[1m'
BRED='\e[91m'
BBLUE='\e[34m'  
BGREEN='\e[92m'
BYELLOW='\e[93m'
RESET='\e[0m'

# Pretty print (function).
info_print () {
    echo -e "${BOLD}${BGREEN}[ ${BYELLOW}•${BGREEN} ] $1${RESET}"
}

# Pretty print for input (function).
input_print () {
    echo -ne "${BOLD}${BYELLOW}[ ${BGREEN}•${BYELLOW} ] $1${RESET}"
}

# Alert user of bad input (function).
error_print () {
    echo -e "${BOLD}${BRED}[ ${BBLUE}•${BRED} ] $1${RESET}"
}

# apparmor
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


# luks encryption choice
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

# sbctl
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

userpass_selector () {
    input_print "Please enter name for user account"
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

# Microcode detector (function).
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

# User enters a hostname (function).
hostname_selector () {
    input_print "Please enter the hostname: "
    read -r hostname
    if [[ -z "$hostname" ]]; then
        error_print "You need to enter a hostname in order to continue."
        return 1
    fi
    return 0
}

# User chooses the locale (function).
locale_selector () {
    input_print "Please insert the locale you use (format: xx_XX. Enter empty to use en_US, or \"/\" to search locales): " locale
    read -r locale
    case "$locale" in
        '') locale="en_US.UTF-8"
            info_print "$locale will be the default locale."
            return 0;;
        '/') sed -E '/^# +|^#$/d;s/^#| *$//g;s/ .*/ (Charset:&)/' /etc/locale.gen | less -M
                clear
                return 1;;
        *)  if ! grep -q "^#\?$(sed 's/[].*[]/\\&/g' <<< "$locale") " /etc/locale.gen; then
                error_print "The specified locale doesn't exist or isn't supported."
                return 1
            fi
            return 0
    esac
}

# User chooses the console keyboard layout (function).
keyboard_selector () {
    input_print "Please insert the keyboard layout to use in console (enter empty to use US, or \"/\" to look up for keyboard layouts): "
    read -r kblayout
    case "$kblayout" in
        '') kblayout="us"
            info_print "The standard US keyboard layout will be used."
            return 0;;
        '/') localectl list-keymaps
             clear
             return 1;;
        *) if ! localectl list-keymaps | grep -Fxq "$kblayout"; then
               error_print "The specified keymap doesn't exist."
               return 1
           fi
        info_print "Changing console layout to $kblayout."
        loadkeys "$kblayout"
        return 0
    esac
}

# settings
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
# create systemd-resolved link to resolv.conf; NOTE (!!!) this MUST be done outside of chroot.
ln -sf /run/systemd/resolve/stub-resolv.conf /mnt/etc/resolv.conf
cp /root/install-arch/settings/network/resolved.conf /mnt/etc/systemd/resolved.conf 
systemctl enable systemd-resolved --root=/mnt &>/dev/null
}


# Welcome screen.
echo -ne "${BOLD}${BYELLOW}
======================================================================

   / \   _ __ ___| |__   | |   (_)_ __  _   ___  __
  / _ \ | '__/ __| '_ \  | |   | | '_ \| | | \ \/ /
 / ___ \| | | (__| | | | | |___| | | | | |_| |>  <
/_/   \_\_|  \___|_| |_| |_____|_|_| |_|\__,_/_/\_\

======================================================================

${RESET}"
info_print "Arch Linux installation script beginning:"

info_print "updating arch-keyring"
timedatectl set-ntp true
pacman -Sy --noconfirm archlinux-keyring >/dev/null

# Setting up keyboard layout.
until keyboard_selector; do : ; done

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
# User choses the locale.
####################################################################################################
until locale_selector; do : ; done

####################################################################################################
# User choses the hostname.
####################################################################################################
until hostname_selector; do : ; done

####################################################################################################
# User sets up the user/root passwords.
####################################################################################################
until userpass_selector; do : ; done

####################################################################################################
# new
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

####################################################################################################
# define variables
####################################################################################################

ESP="$efi_part"
ROOT="$root_part"

####################################################################################################
# Formatting BTRFS filesystem
####################################################################################################

info_print "Formatting BTRFS and creating subvolumes"

mkfs.btrfs "$DEVICE" &>/dev/null
mount "$DEVICE" /mnt
btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@home
btrfs subvolume create /mnt/@srv
btrfs subvolume create /mnt/@snapshots
btrfs subvolume create /mnt/@var_log
btrfs subvolume create /mnt/@var_pkg
btrfs subvolume create /mnt/@var_docker
btrfs subvolume create /mnt/@var_machines
btrfs subvolume create /mnt/@var_portables
umount /mnt

####################################################################################################
# mounting partitions
####################################################################################################

info_print "mounting btrfs subvolumes"

mountopts="ssd,noatime,compress-force=zstd:1,discard=async"
mountopts_secure="ssd,noatime,compress-force=zstd:1,discard=async,nodev,nosuid,noexec"
mount -o "$mountopts",subvol=@ "$DEVICE" /mnt

mkdir -p /mnt/{efi,home,srv,.btrfsroot,.snapshots,var/{log,lib/docker,lib/machines,lib/portables,cache/pacman/pkg}}

mount -o "$mountopts",subvol=@home "$DEVICE" /mnt/home
mount -o "$mountopts",subvol=@srv "$DEVICE" /mnt/srv
mount -o "$mountopts_secure",subvol=@snapshots "$DEVICE" /mnt/.snapshots
mount -o "$mountopts_secure",subvol=@var_log "$DEVICE" /mnt/var/log
mount -o "$mountopts_secure",subvol=@var_pkg "$DEVICE" /mnt/var/cache/pacman/pkg

mount -o "$mountopts",subvol=@var_docker "$DEVICE" /mnt/var/lib/docker
mount -o "$mountopts",subvol=@var_machines "$DEVICE" /mnt/var/lib/machines
mount -o "$mountopts",subvol=@var_portables "$DEVICE" /mnt/var/lib/portables
chattr +C /mnt/var/log

info_print "mounting ESP"
mount -o fmask=0137,dmask=0027 "$ESP" /mnt/efi

####################################################################################################
# Pacstrap (setting up a base system onto the new root).
####################################################################################################

microcode_detector

info_print "Installing the base system (pacstrap)"
pacstrap -K /mnt base base-devel linux linux-headers linux-lts linux-lts-headers "$microcode" linux-firmware apparmor nftables openssh tpm2-tools libfido2 pam-u2f pcsclite man-db efitools efibootmgr reflector zram-generator sudo bash-completion curl wget git rsync stow neovim btrfs-progs snapper snap-pac &>/dev/null

####################################################################################################
# Setting up the hostname.
####################################################################################################

echo "$hostname" > /mnt/etc/hostname

####################################################################################################
# Generating /etc/fstab.
####################################################################################################

info_print "Generating a new fstab"
genfstab -U /mnt >> /mnt/etc/fstab
sed -i 's/subvolid=[0-9]*,//g' /mnt/etc/fstab

####################################################################################################
# Configure selected locale and console keymap
####################################################################################################

sed -i "/^#$locale/s/^#//" /mnt/etc/locale.gen
echo "LANG=$locale" > /mnt/etc/locale.conf
echo "KEYMAP=$kblayout" > /mnt/etc/vconsole.conf

####################################################################################################
# Setting hosts file.
####################################################################################################

info_print "Setting hosts file."

cat > /mnt/etc/hosts <<EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $hostname.localdomain   $hostname
EOF

####################################################################################################
# Setting up the network.
####################################################################################################

info_print "Installing Newtork Utilities"
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

    echo "root=/dev/mapper/cryptroot rootfstype=btrfs rootflags=subvol=/@ rw quiet nowatchdog bgrt_disable zswap.enabled=0" >> /mnt/etc/cmdline.d/root.conf

    if [ "$encrypt_key" = "yes" ]; then
        echo "cryptroot  UUID=$ROOT_UUID  none  fido2-device=auto,password-echo=no,x-systemd.device-timeout=0,timeout=0,no-read-workqueue,no-write-workqueue,discard"  >>  /mnt/etc/crypttab.initramfs
    else
        echo "cryptroot  UUID=$ROOT_UUID  -  password-echo=no,x-systemd.device-timeout=0,timeout=0,no-read-workqueue,no-write-workqueue,discard"  >>  /mnt/etc/crypttab.initramfs
    fi

    cat > /mnt/etc/mkinitcpio.conf <<EOF
    MODULES=(usbhid xhci_hcd hid-generic)
    FILES=()
    HOOKS=(base systemd keyboard autodetect microcode kms sd-vconsole modconf block sd-encrypt filesystems fsck)
EOF
else
    echo "root=UUID=$ROOT_UUID rootfstype=btrfs rootflags=subvol=/@ rw quiet nowatchdog bgrt_disable zswap.enabled=0" >> /mnt/etc/cmdline.d/root.conf

    cat > /mnt/etc/mkinitcpio.conf <<EOF
    MODULES=(usbhid xhci_hcd hid-generic)
    FILES=()
    HOOKS=(base systemd keyboard autodetect microcode kms sd-vconsole modconf block filesystems fsck)
EOF
fi

cat > /mnt/etc/mkinitcpio.d/linux.preset <<EOF
# mkinitcpio preset file to generate UKIs

#ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default')

default_uki="/efi/EFI/Linux/arch-linux.efi"
default_options="--splash=/usr/share/systemd/bootctl/splash-arch.bmp"
EOF

cat > /mnt/etc/mkinitcpio.d/linux-lts.preset <<EOF
# mkinitcpio preset file to generate UKIs

#ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux-lts"

PRESETS=('default')

default_uki="/efi/EFI/Linux/arch-linux-lts.efi"
default_options="--splash=/usr/share/systemd/bootctl/splash-arch.bmp"
EOF
####################################################################################################
# arch-chroot - timezone,clock,locale,mkinitcpio, and snapper setup
####################################################################################################

info_print "Configuring the system (arch-chroot - timezone, system clock, initramfs, Snapper)."

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
    # uncomment this if you do not want efistub boot setup below
    # bootctl install --esp-path=/efi

    # Snapper configuration.
    umount /.snapshots
    rm -r /.snapshots
    snapper --no-dbus -c root create-config /
    btrfs subvolume delete /.snapshots &>/dev/null
    mkdir /.snapshots
    mount -a &>/dev/null
    chmod 750 /.snapshots
EOF

####################################################################################################
# efistub boot
####################################################################################################

info_print "clean up UEFI"

efibootmgr --unicode
efi_boot_id=" "
while [[ -n $efi_boot_id ]]; do
    echo -e "\nDo you want to delete any boot entries?: "
    read -r -p "Enter boot number (empty to skip): " efi_boot_id
    if [[ -n $efi_boot_id ]] ; then
        efibootmgr --bootnum "$efi_boot_id" --delete-bootnum --unicode
    fi
done

info_print "building efistub"

efi_dev=$(lsblk --noheadings --output PKNAME $ESP)
efi_part_num=$(echo $ESP | grep -Eo '[0-9]+$')

arch-chroot /mnt efibootmgr --create --disk /dev/"${efi_dev}" --part ${efi_part_num} --label "arch-linux-lts" --loader "EFI\Linux\arch-linux-lts.efi" --unicode
arch-chroot /mnt efibootmgr --create --disk /dev/"${efi_dev}" --part ${efi_part_num} --label "arch-linux" --loader "EFI\Linux\arch-linux.efi" --unicode

####################################################################################################
# final configurations
####################################################################################################

info_print 'configuring sysctl'
set_sysctl

info_print 'configuring modprobe'
set_modprobe

info_print 'configuring systemd-resolved'
set_systemd_resolved

# ZRAM configuration.
info_print "Configuring ZRAM."
cat > /mnt/etc/systemd/zram-generator.conf <<EOF
[zram0]
zram-size = min(ram / 2, 4 * 1024)
compression-algorithm = zstd
EOF

info_print 'starting nftables firewall'
systemctl enable nftables.service --root=/mnt &>/dev/null

# Pacman eye-candy features.
info_print "Enabling colours, animations, and parallel downloads for pacman."
sed -Ei 's/^#(Color)$/\1\nILoveCandy/;s/^#(ParallelDownloads).*/\1 = 10/' /mnt/etc/pacman.conf

# reflector
cat > /mnt/etc/xdg/reflector/reflector.conf <<EOF
--save /etc/pacman.d/mirrorlist
--country 'United States'
--protocol https
--latest 5
EOF

####################################################################################################
# snapper configurations
####################################################################################################

info_print "configuring snapper"

mkdir -p /mnt/etc/pacman.d/hooks
arch-chroot /mnt chmod a+rx .snapshots
arch-chroot /mnt chown :wheel .snapshots
mkdir -p /mnt/etc/snapper/configs

# root config
cp /root/install-arch/settings/snapper/root.conf /mnt/etc/snapper/configs/root

# efi-hook
cp /root/install-arch/settings/snapper/zzz-signed_uki_backup.hook /mnt/etc/pacman.d/hooks/zzz-signed_uki_backup.hook

systemctl disable snapper-timeline.timer --root=/mnt &>/dev/null
cp /root/install-arch/settings/snapper/snapper_rollback.bash /mnt/usr/local/sbin/snapper-rollback
arch-chroot /mnt chmod +x /usr/local/sbin/snapper-rollback

# backup-volume-delete
cp /root/install-arch/settings/snapper/backup_volume_delete.bash /mnt/usr/local/sbin/backup-volume-delete
arch-chroot /mnt chmod +x /usr/local/sbin/backup-volume-delete

####################################################################################################
# Enabling services
####################################################################################################

info_print "enabling services"
systemctl enable systemd-timesyncd --root=/mnt &>/dev/null

####################################################################################################
# Add user
####################################################################################################

info_print "creating user"
echo "%wheel ALL=(ALL:ALL) ALL" > /mnt/etc/sudoers.d/wheel
arch-chroot /mnt chmod 0440 /etc/sudoers.d/wheel
info_print "Adding the user $username to the system with root privilege."
arch-chroot /mnt useradd -m -G users,wheel -s /bin/bash "$username"
info_print "Setting user password for $username."
echo "$username:$userpass" | arch-chroot /mnt chpasswd

####################################################################################################
# install paru
####################################################################################################

info_print "installing paru"

# temporarily grant NOPASSWD privileges for makepkg
echo "$username ALL=(ALL) NOPASSWD: /usr/bin/makepkg" > /mnt/etc/sudoers.d/"$username"
arch-chroot /mnt chmod 0440 /etc/sudoers.d/"$username"

arch-chroot /mnt /bin/bash -e <<EOF
su $username
cd ~/
git clone https://aur.archlinux.org/paru-bin.git
cd paru-bin
makepkg -si --noconfirm
cd ~/
rm -rf paru-bin
exit
EOF

# remove NOPASSWD privileges for makepkg
arch-chroot /mnt rm /etc/sudoers.d/"$username"

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
    info_print "Enrolling fido2 luks key: the password to unlock the root volume is your user password"
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
fi

####################################################################################################
# final message
####################################################################################################

if [ "$encrypt_root" = "yes" ]; then
  if [ "$encrypt_key" = "yes" ]; then
      info_print "Root partion is encrypted (LUKS) with a single fido2 key. Use systemd-cryptenroll to enroll a backup password or recovery"
  else
      info_print "Root partion is encrypted (LUKS) with user password. Use systemd-cryptenroll to change the password or to change the encryption method to fido2 or tpm"
  fi
fi

info_print "Success, reboot into firmware and enable secure boot: systemctl reboot --firmware-setup"
exit

####################################################################################################
# end
####################################################################################################
