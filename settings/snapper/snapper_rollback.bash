#!/bin/bash

set -e

MOUNTPOINT="/.btrfsroot"
SUBVOL_MAIN="@"
SUBVOL_SNAPSHOTS="@snapshots"
DEV="/dev/mapper/cryptroot"
DATE_PATH_SUFFIX=$(date +%Y%m%d_%H%M%S)
SUBVOL_DATE_PATH="${MOUNTPOINT}/${SUBVOL_MAIN}_backup_${DATE_PATH_SUFFIX}"

if [ -z "$1" ]; then
    echo "Usage: $0 SNAPID"
    exit 1
fi

SNAP_ID="$1"
SUBVOL_MAIN_PATH="${MOUNTPOINT}/${SUBVOL_MAIN}"
SUBVOL_ROLLBACK_SRC="${MOUNTPOINT}/${SUBVOL_SNAPSHOTS}/${SNAP_ID}/snapshot"

echo "You have chosen to rollback to snapshot number '${SNAP_ID}'."
read -r -p "If this is correct, type 'CONFIRM' to proceed with the rollback: " CONFIRMATION
if [ "$CONFIRMATION" != "CONFIRM" ]; then
    echo "Confirmation failed. Exiting rollback."
    exit 1
fi

mkdir -p "${MOUNTPOINT}"

if ! mountpoint -q "${MOUNTPOINT}"; then
    mount -o subvolid=5 "${DEV}" "${MOUNTPOINT}"
fi

if [ ! -d "${SUBVOL_ROLLBACK_SRC}" ]; then
    echo "The specified snapshot (${SUBVOL_ROLLBACK_SRC}) does not exist."
    exit 1
fi

echo "move current @ subvolume to backup subvolume"
mv "${SUBVOL_MAIN_PATH}" "${SUBVOL_DATE_PATH}"

echo "rollback @ subvolume"
btrfs subvolume snapshot "${SUBVOL_ROLLBACK_SRC}" "${SUBVOL_MAIN_PATH}"

if [ -f "${SUBVOL_MAIN_PATH}/var/lib/pacman/db.lck" ]; then
    echo "remove /var/lib/pacman/db.lck from restored snapshot"
    rm "${SUBVOL_MAIN_PATH}/var/lib/pacman/db.lck"
fi

if [ -d "${SUBVOL_ROLLBACK_SRC}/.efibackup/EFI/Linux" ]; then
    echo "rollback /efi partition"
    rsync -a --delete --exclude 'header.img' "${SUBVOL_ROLLBACK_SRC}/.efibackup/" /efi
fi

echo "set new @ subvolume to default subvolume"
btrfs subvolume set-default "${SUBVOL_MAIN_PATH}"

echo "Rollback to snapshot number '${SNAP_ID}' (${SUBVOL_ROLLBACK_SRC}) complete. Reboot to finish."
