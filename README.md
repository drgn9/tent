# Arch Linux Installer (ext4)

An interactive, security-focused Arch Linux installation script with a terminal UI powered by [gum](https://github.com/charmbracelet/gum). It installs a minimal, hardened Arch system on an ext4 root filesystem with Unified Kernel Images (UKI) booted directly via EFISTUB -- no bootloader required.

## Features

- **Interactive TUI** -- guided prompts for every decision; no config files to edit beforehand
- **LUKS encryption** -- optional full-disk encryption using `serpent-xts-plain64` (512-bit key, SHA-512), a cipher chosen for its high security margin
- **TPM2 + PIN unlock** -- optional automatic unlock sealed to the TPM2 chip with a PIN and a recovery key
- **Secure Boot** -- optional enrollment of custom Secure Boot keys via `sbctl`, with automatic UKI and fwupd EFI binary signing
- **Kernel lockdown** -- optional `lockdown=integrity` mode, preventing modification of the running kernel (unsigned module loading, `/dev/mem` writes, kexec, etc.)
- **AppArmor** -- optional mandatory access control with audit logging
- **IOMMU / DMA protection** -- forced IOMMU with strict TLB invalidation and passthrough disabled via kernel cmdline (CPU-specific: `intel_iommu=on` on Intel)
- **Suspend and hibernate disabled** -- sleep-related systemd targets masked, logind configured to ignore sleep events, systemd-sleep disabled
- **Unified Kernel Images** -- both `linux` and `linux-lts` kernels are built as UKIs and booted directly from the EFI System Partition via EFISTUB (no GRUB, no systemd-boot)
- **Firmware updates** -- `fwupd` installed for UEFI and device firmware updates via the Linux Vendor Firmware Service (LVFS)
- **Network choice** -- choose between `iwd + systemd-networkd`, `systemd-networkd` only, or `NetworkManager`
- **DNS over TLS** -- preconfigured `systemd-resolved` with Quad9 and Cloudflare upstream resolvers using opportunistic DNS-over-TLS (falls back to plaintext if TLS is unavailable)
- **Firewall** -- `nftables` enabled out of the box
- **ZRAM swap** -- compressed swap in memory via `zram-generator` (zstd, capped at half RAM or 4 GiB)
- **Kernel hardening** -- sysctl tunables for network firewall hardening (SYN cookies, reverse path filtering, ICMP redirect rejection, source route blocking, broadcast ping rejection, TIME-WAIT protection), watchdog disabled, ZRAM-optimized VM settings
- **Module blacklisting** -- PC speaker, watchdog timers, and FireWire disabled by default; additional configs for disabling Bluetooth, webcam, microphone, and Thunderbolt are included in the settings directory for manual use
- **AUR helper** -- `paru` installed automatically
- **Root account locked** -- root login is disabled; administration is done through `sudo` via the `wheel` group

## Requirements

- A UEFI system (Legacy BIOS is not supported)
- An active internet connection from the Arch live environment
- One or more disks to install to (the script handles partitioning via `fdisk`)
- If enabling Secure Boot: the firmware must be in **Setup Mode** before running the script (see [Secure Boot Preparation](#secure-boot-preparation))

## Quick Start

Boot the [Arch Linux installation media](https://archlinux.org/download/), connect to the internet, then run:

```bash
pacman -Sy --noconfirm git
git clone https://github.com/drgn9/tent.git /root/install-arch
bash /root/install-arch/install_arch_ext4_gum.bash
```

The script must be cloned to `/root/install-arch` -- this is the path it expects for the bundled settings files.

## Walkthrough

The installer guides you through each step interactively. Here is the full sequence:

### 1. Pre-flight checks

The script verifies it is running as root, the system is booted in UEFI mode, and all required settings files are present. It then installs its own dependencies (`gum`, `reflector`, `cryptsetup`, `efibootmgr`) if they are missing.

### 2. Configuration prompts

You are asked to configure the following, in order:

| Prompt | Options | Notes |
|--------|---------|-------|
| LUKS encryption | yes / no | Encrypts the root partition |
| TPM2 + PIN | yes / no | Only shown if encryption is enabled |
| Secure Boot | yes / no | Requires Setup Mode (script checks and exits with instructions if not) |
| AppArmor | yes / no | Installs and enables AppArmor + audit |
| Kernel lockdown | yes / no | Enables `lockdown=integrity` via kernel cmdline |
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
- Security tools: `cryptsetup`, `nftables`, `openssh`, `tpm2-tools`, `libfido2`, `pam-u2f`, `pcsclite`, `efitools`, `fwupd`
- System utilities: `reflector`, `zram-generator`, `sudo`, `bash-completion`, `man-db`, `dosfstools`, `efibootmgr`
- User tools: `curl`, `wget`, `git`, `rsync`, `stow`, `restic`, `rclone`, `age`, `gocryptfs`, `fuse2`, `fuse3`, `vim`, `jq`

Note: `openssh` is installed but the `sshd` service is **not** enabled. Enable it manually after installation if needed.

### 7. System configuration

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

### 8. Boot entries

The script uses `efibootmgr` to manage UEFI boot entries:

1. Existing entries are listed. You can selectively delete entries or skip.
2. Two new EFISTUB entries are created pointing directly at the UKIs:
   - `arch-linux` -> `/efi/EFI/Linux/arch-linux.efi`
   - `arch-linux-lts` -> `/efi/EFI/Linux/arch-linux-lts.efi`

There is no bootloader. The UEFI firmware loads the UKI directly. Use your firmware's boot menu to switch between kernels.

### 9. Hardening

- **sysctl**: TCP SYN cookies, strict reverse path filtering, ICMP redirect rejection, source route blocking, broadcast ping rejection, bogus ICMP error rejection, TIME-WAIT assassination protection (RFC 1337), shared media redirects disabled, NMI watchdog disabled
- **modprobe**: PC speaker, watchdog timers, and FireWire blacklisted; Intel Wi-Fi power save disabled
- **nftables**: firewall service enabled
- **Suspend/hibernate disabled**: sleep-related systemd targets masked (`suspend`, `hibernate`, `hybrid-sleep`, `suspend-then-hibernate`); logind configured to lock on lid close, power off on power key, and ignore suspend/hibernate keys; `systemd-sleep` configured to reject all sleep types
- **ZRAM**: compressed swap (zstd, half RAM up to 4 GiB)
- **pacman**: color output, parallel downloads (10)
- **reflector**: configured for your selected country (HTTPS, top 5 mirrors). Run `reflector` manually or enable `reflector.timer` to auto-update the mirrorlist.

### 10. User account and AUR helper

- A user account is created in the `wheel` group
- `paru` (AUR helper) is installed from the AUR
- Temporary `NOPASSWD` sudo is used only during `paru` installation, then replaced with standard password-required sudo: `%wheel ALL=(ALL:ALL) ALL`

### 11. Root account lockdown

The root account is locked (`passwd -l root`). All administration is done via `sudo`.

### 12. TPM2 enrollment (if enabled)

If you opted for TPM2 + PIN:

1. A TPM2 key is enrolled with a PIN (the PIN is your user password)
2. A recovery key is enrolled (displayed on screen -- **write it down**)
3. The original password keyslot is removed

At boot, the system unlocks when you enter the correct PIN. The recovery key can be used as a fallback if needed.

### 13. Secure Boot (if enabled)

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
install-arch/
├── install_arch_ext4_gum.bash          # Main installer script (interactive, with gum TUI)
├── README.md
├── archive/
│   └── install_arch_ext4.bash          # Alternate installer (without gum, archived)
└── settings/
    ├── modprobe/
    │   ├── blacklist.conf              # Blacklists: PC speaker, watchdog timers
    │   ├── disable-bluetooth.conf      # Optional: disable Bluetooth
    │   ├── disable-firewire.conf       # Disable FireWire (applied by default)
    │   ├── disable-microphone.conf     # Optional: disable microphone
    │   ├── disable-thunderbolt.conf    # Optional: disable Thunderbolt
    │   ├── disable-webcam.conf         # Optional: disable webcam
    │   └── iwlwifi.conf                # Intel Wi-Fi: power save off, 40MHz disabled on 2.4GHz
    ├── network/
    │   ├── 20-wired.network            # systemd-networkd: wired DHCP
    │   ├── 25-wireless.network         # systemd-networkd: wireless DHCP
    │   ├── iwd.main.conf               # iwd: MAC randomization, roaming thresholds
    │   ├── iwd.override.conf           # iwd: 2-second start delay for hardware readiness
    │   ├── NetworkManager.conf         # NetworkManager: use systemd-resolved for DNS
    │   ├── resolved.conf               # systemd-resolved: Quad9 + Cloudflare, opportunistic DoT, no mDNS/LLMNR
    │   └── wait-for-only-one-interface.conf  # Wait for any single interface (faster boot)
    └── sysctl/
        ├── 99-firewall-settings.conf   # Network hardening: SYN cookies, RP filter, no redirects, no source routes, broadcast ping rejection, TIME-WAIT protection
        ├── 99-watchdog-settings.conf   # Disable NMI watchdog
        └── 99-zram-settings.conf       # VM tuning for ZRAM: swappiness 180, page-cluster 0
```

### Optional modprobe configs

The `settings/modprobe/` directory contains additional configs that are **not** applied by default but are available for manual use:

- `disable-bluetooth.conf` -- disable Bluetooth entirely
- `disable-microphone.conf` -- disable the audio input device
- `disable-thunderbolt.conf` -- disable Thunderbolt/USB4
- `disable-webcam.conf` -- disable the USB video class driver

To use any of these after installation, copy them to `/etc/modprobe.d/` and reboot:

```bash
sudo cp disable-bluetooth.conf /etc/modprobe.d/
```

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

- **Cipher**: `serpent-xts-plain64` with a 512-bit key (256-bit effective with XTS) and SHA-512 key derivation
- **Why Serpent**: Serpent was an AES finalist with a more conservative design (32 rounds vs AES's 14). It has a higher security margin than AES at the cost of throughput. It does not benefit from hardware acceleration (AES-NI). This is an intentional trade-off favoring security over raw I/O speed.
- **systemd-based unlock**: uses `sd-encrypt` in the initramfs with `crypttab.initramfs`
- **TPM2 binding** (optional): the unlock key is sealed to the TPM2 chip, requiring a PIN to unseal. A recovery key is also enrolled for emergencies.

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

- Connect to Wi-Fi (if using iwd): `iwctl station wlan0 connect <SSID>`
- Connect to Wi-Fi (if using NetworkManager): `nmtui`
- Check firmware security posture: `fwupdmgr security`
- Install a desktop environment, window manager, or any additional packages via `paru`
- Review and customize sysctl, modprobe, and network configs in `/etc/`

## Error Handling

The script uses `set -euo pipefail` and an ERR trap. If any command fails:

1. Temporary NOPASSWD sudo privileges are removed
2. All mounts under `/mnt` are unmounted
3. The LUKS container is closed (if opened)
4. The script exits with the line number where the failure occurred

## Disclaimer

This script formats disks and partitions. **All data on selected partitions will be destroyed.** Review your choices carefully at the confirmation prompt before proceeding. The authors are not responsible for data loss.

## License

MIT
