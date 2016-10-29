# Introduction

[![DeLUKS: Deniable Linux Unified Key Setup](https://raw.githubusercontent.com/kriswebdev/grub-crypto-deluks/gh-pages/assets/deluks_logo.png)](https://github.com/kriswebdev/grub-crypto-deluks)

This repository presents an implementation of a plausibly Deniable LUKS header in **`cryptsetup`**.

DeLUKS provides most benefits of LUKS and of plausibly [deniable encryption](https://en.wikipedia.org/wiki/Deniable_encryption). The DeUKS header is specified to be indistinguishible from random data. This is like Truecrypt header, but with **GRUB support**, **multiple keyslots** and *(to be implemented)* an **evolutive protection against brute-forcing**.

For system encryption, there is a parrallel project to implement DeLUKS in GRUB Cryptomount: **[grub-crypto-deluks](https://github.com/kriswebdev/grub-crypto-deluks)**. See the [Wiki: System encryption](https://github.com/kriswebdev/cryptsetup-deluks/wiki/System-encryption) for instructions.

Beta available!
===

`cryptsetup-deluks` is leaving the Alpha stage and is now on Beta stage.

Instructions are written for and tested on **Ubuntu 16** (Xenial Xerus).

Install
---

Note: To create a deniable bootable system, check "Setup case" instructions below before installing cryptsetup.

    if ! grep "universe" "/etc/apt/sources.list" &>/dev/null; then echo -e "\e[43mEnable universe repository, through software-properties-gtk""\e[0m"; software-properties-gtk &>/dev/null ; else echo "OK"; fi
    sudo apt-get install git libgcrypt11-dev libdevmapper-dev libpopt-dev uuid-dev libtool automake autopoint debhelper xsltproc docbook-xsl dpkg-dev lvm2
    git clone https://github.com/kriswebdev/cryptsetup-deluks.git
    cd cryptsetup-deluks
    CRYPTLIBDIR=`dirname $(dpkg -L libcryptsetup4 | grep libcryptsetup.so.4$)`
    echo $CRYPTLIBDIR
    ./autogen.sh --prefix=/usr --sbindir=/sbin --libdir="$CRYPTLIBDIR"
    make
    sudo make install
    
Run
---

Help:

    cryptsetup --help

List your drives:

    gnome-disks &
    # or
    blkid; lsblk -o NAME,FSTYPE,SIZE,LABEL,MOUNTPOINT

Run as root:

    sudo su

> Warning: If you are using an **SSD** with sensitive data already present on it, you should sanitize it using **ATA Secure Erase** BEFORE wiping the drive with the command below. ATA Secure Erase tries to erase the otherwise unaccessible disk wear-level blocks and bad blocks. ATA Secure Erase is performed using Linux [hdparm](https://ata.wiki.kernel.org/index.php/ATA_Secure_Erase) or using the SSD manufacturer tools, preferably after upgrading the disk firmware.

[**Wipe your drive** with random data, fast](http://unix.stackexchange.com/questions/72216/fast-way-to-randomize-hd):

    DISK="sdb"
    DISKSIZE=$(</proc/partitions awk '$4=="'"$DISK"'" {print sprintf("%.0f",$3*1024)}')
    apt-get install pv
    # This will erase all data on DISK!
    openssl enc -aes-256-ctr -nosalt \
      -pass pass:"$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64)" \
      </dev/zero |
      pv --progress --eta --rate --bytes --size "$DISKSIZE" |
      dd of=/dev/"$DISK" bs=2M

Create:

    cryptsetup deluksFormat /dev/sdb
    # Debug:
    # cryptsetup -v --debug deluksDump /dev/sdb

Open:

    cryptsetup open /dev/sdb --type deluks deluks_vol

Close:

    cryptsetup close deluks_vol

Setup case: Non-system encryption
---

> This is a simple setup with only one filesystem inside the encrypted volume (no partition table, no LVM). It is used to store data. Please keep in mind that your system keeps logs and tracks of what you do, so if deniability is really your objective, you should consider the system encryption setup case.

First, install cryptsetup, create and open the DeLUKS volume (see above instructions).

Create & mount the filesystem:

    mkfs.ext4 /dev/mapper/deluks_vol
    mkdir /mnt/mount_point
    # To allow the current user to access the mount_point:
    $ sudo chown `id -u -n -r`:`id -g -n -r` /mnt/mount_point
    mount /dev/mapper/deluks_vol /mnt/mount_point
    ...
    umount /mnt/mount_point

Setup case: System encryption
---

See the [Wiki: System encryption](https://github.com/kriswebdev/cryptsetup-deluks/wiki/System-encryption).

DeLUKS Features
===
- **QUICK BOOT!** At GRUB menu, press `c` to get into GRUB shell, then `cryptomount -x /` and your password. That's all!
- Plausibly **DENIABLE!**
  - DeLUKS header and encrypted payload are **indistinguishable from random data**. *"Why is there random data on your unallocated disk space? - I wiped my disk"*
  - Bootloader is nothing more than **GRUB**. If the code is integrated upstream, the setup will even be indistinguishable from mainstream GRUB *"Why do you have a bootloader with deniable decryption feature? - Do I? It's the default GRUB."*
  - **No bootloader password menu**. Base of deny, YOU command the bootloader to ask you for a password, not the other way round. *"Look, I just installed this O.S. on my wiped drive, it's GRUB's only menu choice. Where would I hide something?"*
  - DeLUKS finds encrypted disks by **scanning** & trying to mount all unallocated disk space > 2MiB.
  - **No poorly secured USB key** needed! But use one if you really want to. *"We didn't find any (1) remote header (2) unencrypted keyfile (3) loosely brute-forcable plain dm-crypt keyfile (choose one) on your USB key."*
- LUKS **multiple keyslots**: You can decrypt a disk with any one of 8 passwords. You can change and revok the passwords.
- LUKS protection **against rainbow table** attacks: Master key is encrypted with a salt.
- LUKS **slow brute-forcing**: User password is encrypted with several hash iterations and a salt.
- LUKS **anti-forensic** information splitter: Low risk that the master key could be decrypted with a revoked password (protection against damaged disk blocks storing the revoked keyslot).
- **Pure dm-crypt**, no TrueCrypt.
- **No need for Truecrypt-style "hidden partition"**. Instead, you can create a true partition with a fake O.S. GRUB will by default boot on this fake O.S.

Specifications
===

**TODO**. In the meantime, you can take a look at [deluks.h](https://github.com/kriswebdev/cryptsetup-deluks/blob/master/lib/deluks1/deluks.h).

Basically, only the random-looking salts, master key digest and password-salt-PBKDF2-encrypted key materials are left as-is on disk, like in LUKS header. 

These elements are used to generate and verify the master key, using the install default settings and user-provided password.

Once the master key is recovered, the options header is decrypted to get additional information, including the payload encryption settings or the disk identifier (UUID).

Everything else in the header is random data or encrypted.