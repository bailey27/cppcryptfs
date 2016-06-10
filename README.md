![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
==============

cppcryptfs
------

This software is based on the design of [gocryptfs](https://github.com/rfjakob/gocryptfs), an encrypted overlay filesystem written in Go.

cppcryptfs is an implementation of gocryptfs in C++ for Windows.

It uses the the [Dokany](https://github.com/dokan-dev/dokany) driver and library to provide a virtual fileystem in user mode under Windows.


Current Status
--------------

cppcryptfs is currently pre-alpha, or more accurately: EXPERIMENTAL.


Testing
-------

cppcryptfs seems to work.  It passes 169/171 of the tests in [winfstest](https://github.com/dimov-cz/winfstest).

The two failures are due to file sharing issues.  Due to the nature of how gocryptfs is designed (namely that it is impossible to write to a file unless you are also able to read from it), it is probably impossible to pass these two tests.  It is the opinion of the developer of cppcryptfs that these failures probably don't matter.

Build Requirements
-------
	
	Microsoft Visual Studio 2015 Community Edition
	openssl - https://github.com/openssl/openssl (static build recommended)
	rapidjson - https://github.com/miloyip/rapidjson (for parsing gocryptfs.conf)
	dokany - https://github.com/dokan-dev/dokany

	For Dokany, you probably want to use the binary distribution from here:
		https://github.com/dokan-dev/dokany/releases

	The version currently used with cppcryptfs is Dokany 1.0.0-RC3

Use
-------

cppcryptfs needs to run as administrator.  It needs this to acquire the SE_NAME privilege in Windows for it to work.

cppcryptfs.exe requests administrator privileges automatically which 
pops up the UAC dialog.

Admin privilege is specified in the manifest.  A consequence of this is that
in order to debug or even run it from Visual Studio, you need to run
Visual Studio as administrator.

To make a new encrypted virtual fileystem, first click the "Create" tab.

![Alt text](/screenshots/screenshot_create.png?raw=true "Create tab")

You need to find or create (you can create a directory in the directory selector in the UI) an empty directory to be the root of your filesystem.

It is strongly recommended that this directory reside on an NTFS filesystem.

Then you need to choose a (hopefully strong) password and repeat it.

You can choose to have your filenames encryped using AES256-EME (the default), AES256-CBC, or not to encrypt the filenames (plain text).

When you click on the "Create" button, a gocyrptfs.conf file will be created in the directory.  Unless you choose to use plain text file names, a gocryptfs.diriv will also be created there.  Be sure to backup these files in case they get lost or corrupted.  You won't be able to access any of your data if something happens to gocryptfs.conf.  gocryptfs.conf will never change for the life of your filesystem unless you change the volume label (see bellow).

If you choose to give the volume a label, then the label will be encrypted in gocryptfs.conf.  The maximum volume label length is 32 characters.

You can right click on the mounted drive letter in explorer and change the volume label.  However, doing so will cause cppcryptfs to re-write gocryptfs.conf when the drive is dismounted. This does entail some risk to your gocryptfs.conf.  Again, it's a good a idea to backup your gocryptfs.conf file somewhere.

Then go to the "Mount" tab and select a drive letter and select the folder you
just created the filesystem in.  Then enter the password and click on the "Mount" button.

![Alt text](/screenshots/screenshot_mount.png?raw=true "Mount tab")

Your will then have a new drive letter, and you can use it like a normal drive letter and store your sensitive information there.  The data is encrypted and saved in files in the folder you specified.

For technical details of the cryptographic design of gocryptfs, please visit
the [gocryptfs project page](https://github.com/rfjakob/gocryptfs).


When you are finished using the drive letter, then go to the "Mount" tab and click on "Dismount" or "Dismount All".  The drive letter(s) will be unmounted, and the encryption keys will be erased from memory. 

You can mount as many gocryptfs filesystems as you have unused drive letters available.

cppcryptfs uses VirtualLock() to prevent encryption keys from ending up in the paging file.  If you never hibernate your computer, then you don't have to worry about your keys ever being written to the hard drive.

If you minimize cppcryptfs, then it will hide itself in the system tray.


File name and path length limits
------

If "Long file names" (the default) is specfied when creating the fileystem, or if plain text file names are used, and if the filesystem is located on NTFS, then a file or directory name can be up to 255 characters long, and a full path can be up to 32,000 characters long.

If "Long file names" is not specified and plain text file names aren't used, then the maximum length of a file or directory name is 160 characters.  But the full path limit is still 32,000 characters (assuming NTFS).

When a file name is encrypted, it is converted from UNICODE-16 to UTF-8 which, depending the language, might cause the number of characters to increase.  Then it is encrypted, which causes it to be padded by up to 16 bytes. Then it is base64 encoded, which typically results in a 33% increase in length.  The encrypted file names can therefore be signifcantly longer than the unencrypted names.

Also, the path to the directory in which the encrypted fileystem resides must be pre-pended to the path of the encrypted file names.

Older filesystems, such as FAT32, will limit the total path length to 260 characters.

It is therefore strongly recommended to use NTFS whenever possible.


Compatibility with gocryptfs
------

cppcryptfs strives to be compatible with gocryptfs.  Currently, it is compatible with version 2 of the gocryptfs filesystem.  The only restriction is that only the 128-bit GCM initialization vector length is supported (GCMIV128 in gocrypts.conf).  The legacy  96-bit initialization vector length is not supported.
