![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
==============

cppcryptfs
------

This software is based on the design of [gocryptfs](https://github.com/rfjakob/gocryptfs), an encrypted overlay filesystem written in Go.

cppcryptfs is an implementation of the gocryptfs filesystem in C++ for Windows.

It uses the the [Dokany](https://github.com/dokan-dev/dokany) driver and library to provide a virtual fileystem in user mode under Windows.


Current Status
--------------

cppcryptfs is pre-alpha, or more accurately: EXPERIMENTAL.


Many of the issues are with Dokany.  Many issues are being fixed.  The next Dokany release should
improve things considerably.

Testing
-------

cppcryptfs seems to work.  It passes 170/171 of the tests in [winfstest](https://github.com/dimov-cz/winfstest).

The one failure is due to a file sharing issue.  Due to the nature of how gocryptfs is designed (namely that it is generally impossible to write to a file unless you are also able to read from it), it is probably impossible to pass this one test.  It is the opinion of the developer of cppcryptfs that this failure probably doesn't matter.

Build Requirements
-------
	
	Microsoft Visual Studio 2015 Community Edition
	openssl - https://github.com/openssl/openssl (static build recommended)
	rapidjson - https://github.com/miloyip/rapidjson (for parsing gocryptfs.conf)
	dokany - https://github.com/dokan-dev/dokany

	For Dokany, you probably want to use the binary distribution from here:
		https://github.com/dokan-dev/dokany/releases

	The default (master) branch of cppcryptfs is for building with Dokany 1.0.0-RC3.

	If you would like to build cppcryptfs with the current Dokany source,
	then after you clone cppcryptfs you need to switch to the current_dokany branch of cppcryptfs. 

		git checkout current_dokany


Use
-------

cppcryptfs doesn't require administrator privileges to run, but
if it is not running as administrator, then it won't be able
to acquire the SE_SECURITY_NAME privilege.  SE_SECURITY_NAME is
needed for reading all of the security attributes of files.

cppcryptfs seems to work without SE_SECURITY_NAME.  If you do
run into problems, then you can try running cppcryptfs as adminstrator and see if that helps.

To make a new encrypted virtual fileystem, first click the "Create" tab.

![Alt text](/screenshots/screenshot_create.png?raw=true "Create tab")

You need to find or create (you can create a directory in the directory selector in the UI) an empty directory to be the root of your filesystem.

It is strongly recommended that this directory reside on an NTFS filesystem.

Then you need to choose a (hopefully strong) password and repeat it.  The dialog box will accept at most 255 characters for the password.

You can choose to have your file names encryped using AES256-EME or not to encrypt the file names (plain text).

When you click on the "Create" button, a gocyrptfs.conf file will be created in the directory.  Unless you choose to use plain text file names, a gocryptfs.diriv will also be created there.  Be sure to backup these files in case they get lost or corrupted.  You won't be able to access any of your data if something happens to gocryptfs.conf.  gocryptfs.conf will never change for the life of your filesystem unless you change the volume label (see bellow).

If you choose to give the volume a label, then the label will be encrypted in gocryptfs.conf.  The maximum volume label length is 32 characters. 

The volume label is AES256-GCM encrypted using the master key and a 128-bit random initialization vector and 8 zero bytes of auth data.  Then it is base64 encoded along with the initilization vector and saved in gocryptfs.conf.

The volume label feature is the only cryptographic addition to cppcryptfs that is not part of the cryptographic design of gocryptfs.  If you do not trust that it was designed correctly, then don't use it.

You can right click on the mounted drive letter in File Explorer, select "Properties", and change the volume label.  However, doing so will cause cppcryptfs to re-write gocryptfs.conf when the drive is dismounted. This does entail some risk to your gocryptfs.conf.  Again, it's a good a idea to backup your gocryptfs.conf file somewhere.  

Then go to the "Mount" tab and select a drive letter and select the folder you
just created the filesystem in.  Then enter the password and click on the "Mount" button.

![Alt text](/screenshots/screenshot_mount.png?raw=true "Mount tab")

Your will then have a new drive letter, and you can use it like a normal drive letter and store your sensitive information there.  The data is encrypted and saved in files in the folder you specified.

The file data is encrypted using AES256-GCM.

For technical details of the cryptographic design of gocryptfs, please visit
the [gocryptfs project page](https://github.com/rfjakob/gocryptfs).


When you are finished using the drive letter, go to the "Mount" tab and select the drive letter and click on "Dismount" or click "Dismount All".  The drive letter(s) will be dismounted, and the encryption keys will be erased from memory. 

You can mount as many gocryptfs filesystems as you have unused drive letters available.

Passwords and keys are locked in memory using VirtualLock(). When they are no longer needed, they are erased using SecureZeroMemory() and then unlocked.  If you never hibernate your computer, then you don't have to worry about your passwords or keys ever being written to the hard drive.

If you close the cppcryptfs window, then it will hide itself in the system tray. To exit cppcryptfs, use the Exit button on the mount page or the context menu of the system tray icon.


File name and path length limits
------

If "Long file names" (the default) is specfied when creating the fileystem, or if plain text file names are used, and if the filesystem is located on NTFS, then a file or directory name can be up to 255 characters long, and a full path can be up to 32,000 characters long.

If "Long file names" is not specified and plain text file names aren't used, then the maximum length of a file or directory name is 160 characters.  But the full path limit is still 32,000 characters (assuming NTFS).

When a file name is encrypted, it is converted from UNICODE-16 to UTF-8 which, depending the language, might cause the number of characters to increase.  Then it is encrypted, which causes it to be padded by up to 16 bytes. Then it is base64 encoded, which typically results in a 33% increase in length.  The encrypted file names can therefore be signifcantly longer than the unencrypted names.

Also, the path to the directory in which the encrypted fileystem resides must be pre-pended to the path of the encrypted file names.

Older filesystems, such as FAT32, will limit the total path length to 259 characters.

It is therefore strongly recommended to use NTFS whenever possible.

A lot of Windows progams, including File Explorer that comes with Windows, have problems with long paths.  If you use encrypted file names, then you might need to use a third-party file manager that handles long file paths if you want to move the root of your encrypted filesystem.  It's a good idea to copy it and then delete the old one instead of moving it in case your file manager has problems.


Compatibility with gocryptfs
------

cppcryptfs is compatible with version 2 of the gocryptfs filesystem.  This is the version of the filesystem used by version 1.0 of the gocryptfs software.
