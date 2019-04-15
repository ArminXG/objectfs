# ObjectFS

## Introduction
ObjectFS is a FUSE filesystem written with the intention of having a full POSIX
compatible filesystem on a network share without the POSIX features.

A network share like SMB or any some cloud based filesystems do not support
features like file ownerships, modes and permissions, hardlinks and extended attributes.

ObjectFS stores all data including the POSIX meta data as an object (file) on the
remote system. This allows all features of a known Linux filesystem on top
of a network share that normaly doesn't allow that.

## Usage
The recommended command to run objectfs is:

  objectfs -p /path/to/networkdrive /path/to/mountpoint

To umount, use
  fusermount -u /path/to/mountpoint


