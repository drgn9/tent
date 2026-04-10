# Arch Linux Installer (ext4)

An interactive, security-focused Arch Linux installation script with a terminal UI powered by [gum](https://github.com/charmbracelet/gum). It installs a hardened Arch system with a desktop environment on an ext4 root filesystem with Unified Kernel Images (UKI) booted directly via EFISTUB -- no bootloader required.

## Features

- **Interactive TUI** -- guided prompts for every decision; no config files to edit beforehand
- **Desktop environment** -- choose between Niri (tiling Wayland compositor) or GNOME; packages are managed via external `.conf` files for easy customization
- **LUKS encryption** -- optional full-disk encryption using `aes-xts-plain64` (512-bit key, SHA-512)
- **TPM2 + PIN unlock** -- optional automatic unlock sealed to the TPM2 chip with a PIN and a recovery key
- **FIDO2 + PIN unlock** -- optional LUKS unlock with a FIDO2 security key (e.g., YubiKey) and a PIN, with optional backup key enrollment and a recovery key
- **Secure Boot** -- optional enrollment of custom Secure Boot keys via `sbctl`, with automatic UKI and fwupd EFI binary signing
- **Kernel lockdown** -- optional `lockdown=integrity` mode, preventing modification of the running kernel (unsigned module loading, `/dev/mem` writes, kexec, etc.)
- **AppArmor** -- optional mandatory access control with audit logging
- **Hardware toggles** -- interactive prompts to disable Bluetooth and Thunderbolt via modprobe blacklists
- **USBGuard** -- installed but not enabled; configure after first boot to whitelist trusted USB devices
- **IOMMU / DMA protection** -- forced IOMMU with strict TLB invalidation and passthrough disabled via kernel cmdline (CPU-specific: `intel_iommu=on` on Intel)
- **Suspend and hibernate disabled** -- sleep-related systemd targets masked, logind configured to ignore sleep events, systemd-sleep disabled
- **Unified Kernel Images** -- both `linux` and `linux-lts` kernels are built as UKIs and booted directly from the EFI System Partition via EFISTUB (no GRUB, no systemd-boot)
- **Firmware updates** -- `fwupd` installed for UEFI and device firmware updates via the Linux Vendor Firmware Service (LVFS)
- **Network choice** -- choose between `iwd + systemd-networkd`, `systemd-networkd` only, or `NetworkManager`
- **DNS over TLS** -- preconfigured `systemd-resolved` with Quad9 and Cloudflare upstream resolvers using opportunistic DNS-over-TLS (falls back to plaintext if TLS is unavailable)
- **Tailscale** -- installed and enabled; operator set via post-install instructions
- **ZRAM swap** -- compressed swap in memory via `zram-generator` (zstd, capped at half RAM or 4 GiB)
- **Kernel hardening** -- sysctl tunables for network firewall hardening (SYN cookies, reverse path filtering, ICMP redirect rejection, source route blocking, broadcast ping rejection, TIME-WAIT protection), watchdog disabled, ZRAM-optimized VM settings
- **Core dump disabled** -- disabled at the systemd system, user, and security limits levels
- **Module blacklisting** -- PC speaker, watchdog timers, and FireWire disabled by default; additional configs for disabling Bluetooth, webcam, microphone, and Thunderbolt are included in the settings directory for manual use
- **AUR helper** -- `paru` installed automatically so AUR packages can be managed manually after installation
- **Root account locked** -- root login is disabled; administration is done through standard `sudo` via the `wheel` group
- **External package lists** -- all packages are defined in plain-text `.conf` files under `packages/`, making it easy to customize without editing the main script

## Requirements

- A UEFI system (Legacy BIOS is not supported)
- An active internet connection from the Arch live environment
- One or more disks to install to (the script handles partitioning via `fdisk`)
- If enabling Secure Boot: the firmware must be in **Setup Mode** before running the script (see [Secure Boot Preparation](#secure-boot-preparation))

## Quick Start

Boot the [Arch Linux installation media](https://archlinux.org/download/), connect to the internet, then run:

```bash
pacman -Sy --noconfirm git
git clone https://github.com/drgn9/tent.git
bash tent/install_arch_ext4_gum.bash
```

The script auto-detects its own location, so it can be cloned to any directory.

## Walkthrough

The installer guides you through each step interactively. Here is the full sequence:

### 1. Pre-flight checks

The script verifies it is running as root, the system is booted in UEFI mode, and all required settings and package files are present. It then installs its own dependencies (`gum`, `reflector`, `cryptsetup`, `efibootmgr`) if they are missing.

### 2. Configuration prompts

You are asked to configure the following, in order:

| Prompt | Options | Notes |
|--------|---------|-------|
| LUKS encryption | yes / no | Encrypts the root partition |
| Unlock method | TPM2+PIN / FIDO2+PIN / Passphrase only | Only shown if encryption is enabled |
| Backup FIDO2 key | yes / no | Only shown if FIDO2 is selected |
| Secure Boot | yes / no | Requires Setup Mode (script checks and exits with instructions if not) |
| AppArmor | yes / no | Installs and enables AppArmor + audit |
| Kernel lockdown | yes / no | Enables `lockdown=integrity` via kernel cmdline |
| Disable Bluetooth | yes / no | Blacklists Bluetooth modules via modprobe |
| Disable Thunderbolt | yes / no | Blacklists Thunderbolt modules via modprobe |
| Desktop | Niri / GNOME | Selects the desktop environment to install |
| Network stack | iwd + systemd-networkd / systemd-networkd only / NetworkManager | |
| Hostname | free text | Validated against RFC 1123 |
| Timezone | region / city picker | Searchable list from `/usr/share/zoneinfo` |
| Mirror country | country picker | Searchable list from `reflector --list-countries` |
| Username | free text | Validated: lowercase, starts with letter or `_`, max 32 chars |
| Password | masked input | Entered twice for confirmation |

A summary of all choices is displayed. You must confirm before anything is written to disk.

### 3. Secure wipe (optional)

You can select one or more disks to securely wipe. Each selected disk is overwritten with zeros through a temporary dm-crypt mapping (`aes-xts-plain64` with a random key from `/dev/urandom`). Select **Skip** when done.

### 4. Partitioning

You can select one or more disks to partition using `fdisk`. The script opens an interactive `fdisk` session for each selected disk. Select **Skip** when done.

You need at minimum:

- An **EFI System Partition** (recommended: 1 GiB, type `EFI System`)
- A **root partition** (type `Linux filesystem`)
- Optionally, a **snapshot partition** for backups

### 5. Partition assignment

You select which partition serves each role:

- **EFI partition** -- formatted as FAT32, mounted at `/efi` with restrictive permissions (`fmask=0137,dmask=0027`)
- **Root partition** -- optionally encrypted with LUKS, then formatted as ext4, mounted at `/`
- **Snapshot partition** (optional) -- formatted as ext4, mounted at `/.snapshots`

The script validates that all selected partitions are distinct.

### 6. Base system installation

`pacstrap` installs the base system including:

- `base`, `base-devel`, `linux`, `linux-lts` (with headers and firmware)
- CPU microcode (auto-detected: `amd-ucode` or `intel-ucode`)
- Security tools: `cryptsetup`, `nftables`, `openssh`, `tpm2-tools`, `libfido2`, `pam-u2f`, `pcsclite`, `pcsc-tools`, `audit`, `efitools`, `fwupd`, `usbguard`
- System utilities: `reflector`, `zram-generator`, `sudo`, `bash-completion`, `man-db`, `dosfstools`, `efibootmgr`
- User tools: `curl`, `wget`, `git`, `rsync`, `stow`, `restic`, `rclone`, `age`, `gocryptfs`, `fuse2`, `fuse3`, `vim`, `jq`

Note: `openssh` is installed but the `sshd` service is **not** enabled. Enable it manually after installation if needed.

### 7. Desktop packages

The script installs desktop packages from external `.conf` files via `pacman -S --needed --noconfirm -` (reading package names from stdin). This is done inside `arch-chroot` after the base system is in place.

**Always installed:**

- **Base CLI tools** (`packages/base.conf`): 33 packages including tmux, btop, fastfetch, rsync, rclone, restic, etc.
- **Tailscale**: installed and `tailscaled.service` enabled
- **Desktop common** (`packages/desktop-base.conf`): 55 packages including mesa, PipeWire audio stack, fonts, yubikey tools, bitwarden, keepassxc, alacritty, libreoffice, android tools, etc.
- **GPU drivers**: auto-detected via `lspci` -- Intel (`packages/desktop-driver-intel.conf`) or AMD (`packages/desktop-driver-amd.conf`)

**Optional installer prompts**:

- **Dev tools** (`packages/base-dev.conf`): neovim, lazygit, fzf, ripgrep, bat, starship, etc.
- **Docker** (`packages/base-docker.conf`): docker, docker-buildx, docker-compose

**Based on desktop choice:**

- **Niri** (`packages/desktop-niri.conf`): niri, swaylock, swayidle, waybar, fuzzel, mako, Qt/Kvantum theming, xdg-desktop-portal-gtk, xwayland-satellite
- **GNOME** (`packages/desktop-gnome.conf`): gnome-shell, gnome-control-center, GDM, nautilus, evince, CUPS printing

### 8. System configuration

The script configures:

- `/etc/fstab` (generated from current mounts, using UUIDs)
- Hostname and `/etc/hosts`
- Locale (`en_US.UTF-8`)
- Console keymap (`us`)
- Network stack (based on your earlier choice)
- `systemd-resolved` with opportunistic DNS-over-TLS (Quad9 primary, Cloudflare fallback; falls back to plaintext if TLS is unavailable)
- `systemd-timesyncd` for NTP time synchronization
- `mkinitcpio` with systemd-based hooks and UKI presets (no fallback initramfs -- UKIs only)
- Kernel command line via `/etc/cmdline.d/` (root device, quiet boot, watchdog disabled, zswap disabled, BGRT disabled)
- IOMMU hardening via `/etc/cmdline.d/iommu.conf` (`iommu=force`, `iommu.passthrough=0`, `iommu.strict=1`, plus `intel_iommu=on` on Intel)
- Kernel lockdown via `/etc/cmdline.d/lockdown.conf` (if enabled)
- `crypttab.initramfs` (if encryption is enabled)
- AppArmor kernel parameters and parser optimizations (if enabled)
- Timezone, hardware clock, and locale generation (inside `arch-chroot`)

### 9. Boot entries

The script uses `efibootmgr` to manage UEFI boot entries:

1. Existing entries are listed. You can selectively delete entries or skip.
2. Two new EFISTUB entries are created pointing directly at the UKIs:
   - `arch-linux` -> `/efi/EFI/Linux/arch-linux.efi`
   - `arch-linux-lts` -> `/efi/EFI/Linux/arch-linux-lts.efi`

There is no bootloader. The UEFI firmware loads the UKI directly. Use your firmware's boot menu to switch between kernels.

### 10. Hardening

- **sysctl**: TCP SYN cookies, strict reverse path filtering, ICMP redirect rejection, source route blocking, broadcast ping rejection, bogus ICMP error rejection, TIME-WAIT assassination protection (RFC 1337), shared media redirects disabled, NMI watchdog disabled
- **modprobe**: PC speaker, watchdog timers, and FireWire blacklisted; Intel Wi-Fi power save disabled; optionally Bluetooth and Thunderbolt disabled (based on prompts)
- **Core dumps disabled**: at the systemd system level, user level, and security limits level
- **Suspend/hibernate disabled**: sleep-related systemd targets masked (`suspend`, `hibernate`, `hybrid-sleep`, `suspend-then-hibernate`); logind configured to lock on lid close, power off on power key, and ignore suspend/hibernate keys; `systemd-sleep` configured to reject all sleep types
- **ZRAM**: compressed swap (zstd, half RAM up to 4 GiB)
- **pacman**: color output, parallel downloads (10)
- **reflector**: configured for your selected country (HTTPS, top 5 mirrors). Run `reflector` manually or enable `reflector.timer` to auto-update the mirrorlist.

### 11. User account and AUR helper

- A user account is created in the `wheel` group
- `paru` (AUR helper) is installed from the AUR
- Temporary `NOPASSWD` sudo is used only while bootstrapping `paru`, then replaced with standard password-required sudo: `%wheel ALL=(ALL:ALL) ALL`

### 12. Root account lockdown

The root account is locked (`passwd -l root`). All administration is done via `sudo`.

### 13. LUKS key enrollment (if TPM2 or FIDO2 is enabled)

#### TPM2 + PIN

1. A TPM2 key is enrolled with a PIN
2. A recovery key is enrolled (displayed on screen -- **write it down**)
3. The original password keyslot is removed

At boot, the system unlocks when the TPM2 unseals the key and you enter the correct PIN. The recovery key can be used as a fallback if the TPM is cleared or the firmware changes.

#### FIDO2 + PIN

1. You are prompted to insert your primary FIDO2 key
2. The primary FIDO2 key is enrolled with a client PIN (Ed25519 / `eddsa` credential algorithm)
3. If you opted for a backup key: you are prompted to swap keys, then the backup FIDO2 key is enrolled with its own PIN
4. A recovery key is enrolled (displayed on screen -- **write it down**)
5. The original password keyslot is removed

At boot, `sd-encrypt` tries to detect a FIDO2 device. If found, it prompts for the FIDO2 PIN and unlocks. If no FIDO2 device is present within 30 seconds, it falls back to a passphrase prompt where you can enter the recovery key.

Either the primary or backup FIDO2 key will work at the boot prompt -- they are independent LUKS keyslots.

### 14. Secure Boot (if enabled)

If you opted for Secure Boot:

1. `sbctl` is installed
2. Custom Secure Boot keys are created and enrolled (including Microsoft's keys for hardware compatibility)
3. Both UKIs and the fwupd EFI binary (`fwupdx64.efi`) are signed with `sbctl sign -s` (persistent signing -- future kernel and fwupd updates are automatically re-signed via pacman hook)
4. Kernels are reinstalled to trigger the signing hook

## Secure Boot Preparation

If you want to enable Secure Boot, you must put your firmware into **Setup Mode** before running the script:

1. Reboot into firmware setup: `systemctl reboot --firmware-setup`
2. Navigate to the Secure Boot settings
3. Delete/clear all Secure Boot keys (PK, KEK, db)
4. Ensure Secure Boot remains **enabled** (not disabled -- it must be on but with no keys)
5. Save and exit

The script checks for Setup Mode and will exit with instructions if it is not enabled.

## Firmware Updates

`fwupd` is installed for updating UEFI/BIOS and device firmware via the Linux Vendor Firmware Service (LVFS). Updates are always manual -- nothing is downloaded or applied automatically.

```bash
# Refresh the metadata catalog from LVFS
fwupdmgr refresh

# Check for available firmware updates
fwupdmgr get-updates

# Apply updates (interactive, prompts for confirmation per device)
fwupdmgr update

# Audit your system's firmware security posture
fwupdmgr security
```

UEFI/BIOS firmware updates are staged to the EFI System Partition and applied on the next reboot (the firmware processes a UEFI capsule, then reboots again into the updated firmware). Non-UEFI firmware updates (NVMe, peripherals) are typically applied live.

If Secure Boot is enabled, the `fwupdx64.efi` binary used during UEFI capsule updates is signed by `sbctl` at install time. The `--save` flag ensures it is automatically re-signed when the `fwupd` package is updated.

## Loading Out-of-Tree Kernel Modules

If kernel lockdown (`lockdown=integrity`) is enabled, the kernel will only load modules signed with a trusted key. All in-tree modules shipped with the `linux` and `linux-lts` packages are already signed and work without issue. Out-of-tree modules (such as the NVIDIA proprietary driver or DKMS-built modules) must be signed manually.

### Option 1: Use in-tree alternatives

For NVIDIA GPUs (Turing / RTX 2000 series and newer), consider using `nvidia-open` -- NVIDIA's open-source kernel modules that are built and signed as part of the standard kernel package.

### Option 2: Sign the module yourself

1. Generate a signing key pair:

   ```bash
   openssl req -new -x509 -newkey rsa:4096 -keyout /etc/kernel-signing/MOK.key \
       -outform DER -out /etc/kernel-signing/MOK.der -days 36500 -subj "/CN=Module Signing Key/" -nodes
   ```

2. Enroll the public key in the kernel's trusted keyring via MOK (Machine Owner Key):

   ```bash
   mokutil --import /etc/kernel-signing/MOK.der
   ```

   You will be prompted to set a one-time password. On the next reboot, the Shim MOK Manager will ask you to confirm the enrollment using that password.

   Note: this requires `shim` to be in the boot chain. If you are using pure EFISTUB without Shim, you can instead add the key to the UEFI `db` via `sbctl`:

   ```bash
   sbctl enroll-keys --custom /etc/kernel-signing/MOK.der
   ```

3. Sign the module after each build:

   ```bash
   /usr/src/linux-$(uname -r)/scripts/sign-file sha256 \
       /etc/kernel-signing/MOK.key /etc/kernel-signing/MOK.der /path/to/module.ko
   ```

4. For DKMS modules, you can automate signing by configuring `/etc/dkms/framework.conf`:

   ```
   sign_tool="/etc/kernel-signing/dkms-sign.sh"
   ```

   Where `dkms-sign.sh` calls `sign-file` with your key pair.

### Option 3: Disable lockdown

If signing is not practical, you can remove lockdown by deleting the cmdline drop-in and rebuilding the UKI:

```bash
sudo rm /etc/cmdline.d/lockdown.conf
sudo mkinitcpio -P
```

If Secure Boot is enabled, re-sign the UKIs after rebuilding:

```bash
sudo sbctl sign-all
```

## Repository Structure

```
tent/
├── install_arch_ext4_gum.bash          # Main installer script
├── README.md
├── packages/                           # Package lists (one package per line)
│   ├── base.conf                       # Base CLI tools (33 packages)
│   ├── base-dev.conf                   # Dev tools (toggle manually, 29 packages)
│   ├── base-docker.conf                # Docker (toggle manually, 3 packages)
│   ├── desktop-base.conf               # Desktop common: mesa, sound, fonts, android (55 packages)
│   ├── desktop-driver-intel.conf       # Intel GPU drivers (auto-detected)
│   ├── desktop-driver-amd.conf         # AMD GPU drivers (auto-detected)
│   ├── desktop-niri.conf               # Niri WM + Qt/Kvantum theming (22 packages)
│   └── desktop-gnome.conf              # GNOME + apps + printing (19 packages)
└── settings/
    ├── modprobe/
    │   ├── blacklist.conf              # Blacklists: PC speaker, watchdog timers
    │   ├── disable-bluetooth.conf      # Disable Bluetooth (applied if selected)
    │   ├── disable-firewire.conf       # Disable FireWire (applied by default)
    │   ├── disable-microphone.conf     # Optional: disable microphone (manual)
    │   ├── disable-thunderbolt.conf    # Disable Thunderbolt (applied if selected)
    │   ├── disable-webcam.conf         # Optional: disable webcam (manual)
    │   ├── iwlwifi.conf                # Intel Wi-Fi: power save off
    │   └── security-blacklist.conf     # Security-related module blacklists
    ├── network/
    │   ├── 20-wired.network            # systemd-networkd: wired DHCP
    │   ├── 25-wireless.network         # systemd-networkd: wireless DHCP
    │   ├── iwd.main.conf               # iwd: MAC randomization, roaming thresholds
    │   ├── iwd.override.conf           # iwd: 2-second start delay for hardware readiness
    │   ├── NetworkManager.conf         # NetworkManager: use systemd-resolved for DNS
    │   ├── resolved.conf               # systemd-resolved: Quad9 + Cloudflare, opportunistic DoT
    │   └── wait-for-only-one-interface.conf  # Wait for any single interface (faster boot)
    ├── polkit/
    │   └── 00-udisks-wheel.rules       # Allow wheel group to manage disks via udisks2
    ├── security/
    │   └── disable-coredump.conf       # Disable core dumps via security limits
    ├── sysctl/
    │   ├── 99-firewall-settings.conf   # Network hardening: SYN cookies, RP filter, no redirects
    │   ├── 99-hardening.conf           # Additional kernel hardening settings
    │   ├── 99-watchdog-settings.conf   # Disable NMI watchdog
    │   └── 99-zram-settings.conf       # VM tuning for ZRAM: swappiness 180, page-cluster 0
    └── systemd/
        ├── disable-coredump-system.conf  # Disable core dumps at system level
        └── disable-coredump-user.conf    # Disable core dumps at user level
```

### Optional modprobe configs

The `settings/modprobe/` directory contains additional configs that are **not** applied by default but are available for manual use:

- `disable-microphone.conf` -- disable the audio input device
- `disable-webcam.conf` -- disable the USB video class driver

To use any of these after installation, copy them to `/etc/modprobe.d/` and reboot:

```bash
sudo cp disable-microphone.conf /etc/modprobe.d/
```

Note: `disable-bluetooth.conf` and `disable-thunderbolt.conf` are applied automatically if you select those options during installation.

## Partition Layout

The script expects you to create partitions manually via `fdisk`. A typical layout:

| Partition | Type | Size | Filesystem | Mount |
|-----------|------|------|------------|-------|
| EFI | EFI System | 1 GiB | FAT32 | `/efi` |
| Root | Linux filesystem | Remainder | ext4 (optionally inside LUKS) | `/` |
| Snapshots | Linux filesystem | 20-50 GiB (optional) | ext4 | `/.snapshots` |

The EFI partition is sized at 1 GiB to accommodate two UKIs (each ~100-150 MiB) with room for future kernels.

## Encryption Details

When LUKS encryption is enabled:

- **Cipher**: `aes-xts-plain64` with a 512-bit key (256-bit effective with XTS) and SHA-512 key derivation
- **systemd-based unlock**: uses `sd-encrypt` in the initramfs with `crypttab.initramfs`
- **TPM2 binding** (optional): the unlock key is sealed to the TPM2 chip, requiring a PIN to unseal. A recovery key is also enrolled for emergencies.
- **FIDO2 binding** (optional): the unlock key is tied to a FIDO2 security key with a client PIN (Ed25519 credential). A backup FIDO2 key and a recovery key can also be enrolled. If no FIDO2 device is present at boot, `sd-encrypt` falls back to a passphrase prompt after a 30-second timeout.

## Post-Installation

After the script completes:

1. **Reboot into firmware setup** to enable Secure Boot (if you configured it):
   ```bash
   systemctl reboot --firmware-setup
   ```
2. Enable Secure Boot in your firmware settings, then save and exit.
3. The system should boot into the `arch-linux` UKI. Use the firmware boot menu (usually F12 or Esc at POST) to select `arch-linux-lts` if needed.
4. Log in with the username and password you set during installation.

### First steps after reboot

Run the post-install commands printed at the end of installation:

```bash
# Set yourself as the Tailscale operator
sudo tailscale set --operator=$USER

# Enable the SSH agent
systemctl --user enable --now ssh-agent.socket
```

If you installed **Niri**, also run:

```bash
# Set dark mode
dconf write /org/gnome/desktop/interface/color-scheme "'prefer-dark'"

# Configure GTK and icon themes
nwg-look

# Configure Qt theme
kvantummanager
```

Additional first steps:

- Connect to Wi-Fi (if using iwd): `iwctl station wlan0 connect <SSID>`
- Connect to Wi-Fi (if using NetworkManager): `nmtui`
- Connect to Tailscale: `tailscale up`
- Check firmware security posture: `fwupdmgr security`
- Configure USBGuard: plug in all trusted USB devices, then run:
  ```bash
  sudo usbguard generate-policy > /etc/usbguard/rules.conf
  sudo systemctl enable --now usbguard
  ```
  Add your username to `IPCAllowedUsers` in `/etc/usbguard/usbguard-daemon.conf` for non-root CLI access.
- Review and customize sysctl, modprobe, and network configs in `/etc/`

## Customizing Packages

All packages are defined in plain-text files under `packages/`. Each file contains one package name per line. To customize:

- **Add a package**: append its name to the appropriate `.conf` file
- **Remove a package**: delete its line from the `.conf` file
- **Dev and Docker packages**: answer the optional package prompts during the installer run

No other changes to the main script are needed.

## Error Handling

The script uses `set -Eeuo pipefail` and an ERR trap. If any command fails:

1. Temporary NOPASSWD sudo privileges are removed
2. All mounts under `/mnt` are unmounted
3. The LUKS container is closed (if opened)
4. The script exits with the line number where the failure occurred

## Disclaimer

This script formats disks and partitions. **All data on selected partitions will be destroyed.** Review your choices carefully at the confirmation prompt before proceeding. The authors are not responsible for data loss.

## License

MIT
