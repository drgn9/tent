#!/usr/bin/env -S bash -e

# run this script after booting to a restored snapshot. this script deletes the backup directories containg the previous @ subvolume(s)

# Set the mount point and backup prefix
MOUNT_POINT="/.btrfsroot"
BACKUP_PREFIX="@_backup_"

# Check if MOUNT_POINT directory exists
if [ ! -d "$MOUNT_POINT" ]; then
    echo "Mount point $MOUNT_POINT does not exist, aborting."
    exit 1
fi

# Mount the Btrfs root filesystem
mount -o subvolid=5 /dev/mapper/cryptroot $MOUNT_POINT

# Check if the mount was successful
if mountpoint -q  "$MOUNT_POINT"; then

    # List all the directories to be deleted and prompt for confirmation
    echo "The following directories will be deleted:"
    for file in "$MOUNT_POINT"/"$BACKUP_PREFIX"*; do
        if [ -e "$file" ]; then
            echo "$(basename "$file")"
        fi
    done

    # wait for user confirmation here
    read -p "Are you sure you want to delete the above directories? (y/n) " -n 1 -r

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "${MOUNT_POINT:?}/${BACKUP_PREFIX:?}"*
    else
        echo "Deletion cancelled by user."
    fi

    # Unmount the Btrfs filesystem
    umount "$MOUNT_POINT"
else
    echo "Mounting $MOUNT_POINT failed, aborting."
fi
