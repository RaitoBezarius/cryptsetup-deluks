# Introduction



[![DeLUKS: Deniable Linux Unified Key Setup](https://raw.githubusercontent.com/kriswebdev/grub-crypto-deluks/gh-pages/assets/deluks_logo.png)](https://github.com/kriswebdev/grub-crypto-deluks)

This repository is a work in progress to specify and implement a Deniable LUKS header in **Cryptsetup**.

DeLUKS will provide most benefits of LUKS and of plausibly [deniable encryption](https://en.wikipedia.org/wiki/Deniable_encryption).

Note there is a parrallel project to implement DeLUKS in GRUB Cryptomount: **[grub-crypto-deluks](https://github.com/kriswebdev/grub-crypto-deluks)**.

Alpha now available!
===

Beware: Header structure may change until Release Candidate: no backward compatibility.

Install
---

    git clone https://github.com/kriswebdev/cryptsetup-deluks.git
    cd cryptsetup-deluks
    sudo apt-get install libgcrypt11-dev libdevmapper-dev libpopt-dev uuid-dev libtool automake autopoint debhelper xsltproc docbook-xsl dpkg-dev
    ./autogen.sh  --sbindir=/sbin
    make
    
Now, use `./src/cryptsetup` to run cryptsetup or `sudo make install` to install permanently.
    
Run
---

Only full disk encryption is available for now.

NB:
- Use `./src/cryptsetup` instead of `cryptsetup` if not installed.
- Consider [wiping your drive](http://unix.stackexchange.com/a/172088/149815) first


Help:

    cryptsetup --help

List your drives:

    gnome-disks &

Initial setup - Create DeLUKS header:

    # Run deluksFormat as root or make the drive accessible to the current user:
    # sudo chown ${USER}:disk:disk /dev/sdb
    cryptsetup -v --debug deluksFormat /dev/sdb
    cryptsetup -v --debug deluksDump /dev/sdb
    sudo mkdir /media/mount_point

Open:

    sudo cryptsetup open /dev/sdb --type deluks deluks_vol
    sudo mount /dev/mapper/deluks_vol /media/my_device

Initial setup - Format:

    mkfs.ext4 /dev/mapper/deluks_vol
    
Close:

    sudo umount /media/my_device
    sudo cryptsetup close deluks_vol

Expected Features
===
- **QUICK BOOT!** At GRUB menu, press `c` to get into GRUB shell, then `cryptomount -x` and your password. That's all!
- **DENIABLE!**
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

Theoretical limitations and workarounds
===
It is difficult to write the header encryption parameters on disk without compromising deniability character or security.
Therefore the Master key / keyslots encryption parameters should use DeLUKS default presets of the installed GRUB version (or be provided through command-line arguments at each boot as an annoying last resort).

However, default presets hard-coded in GRUB-cryptomount shall regularly evolve to follow security best practices.
Hence, once GRUB is updated with newer DeLUKS default presets, it shall behave according to this procedure:
1. GRUB-cryptomount will try to decrypt the disks using the latests presets.
2. If GRUB-cryptomount fails to decrypt any disk, it will try with older presets.
3. If GRUB-cryptomount succeds to decrypt any disk with older presets, it shall warn the user to re-create the DeLUKS header with newer presets using cryptsetup. And continue booting.

Points 1 and 2 are similar to Truecrypt behavior.

The disk payload encryption settings can be changed as these options are encrypted.
If GRUB-cryptomount detects the disk payload encryption settings to be obsolete, it shall warn the user to re-create the DeLUKS header and to re-encrypt the drive with newer presets using cryptsetup. And continue booting.
