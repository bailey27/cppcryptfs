![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
==============

cppcryptfs
------

This software is based on the design of [gocryptfs](https://github.com/rfjakob/gocryptfs), an encrypted overlay filesystem written in Go.

cppcryptfs is an implementation of the gocryptfs filesystem in C++ for Windows.

It uses the the [Dokany](https://github.com/dokan-dev/dokany) driver and library to provide a virtual fileystem in user mode under Windows.


Current Status
--------------

The developer has been using cppcryptfs in forward (normal) mode for over a year and hasn't lost
any data.  At least one other person is using it.  There haven't been any serious issues reported.

Reverse mode undergone only limited testing by the developer.

Binary releases are on the [releases page](https://github.com/bailey27/cppcryptfs/releases).

Testing
-------

cppcryptfs seems to work.  

It passes 492/492 tests in [winfstest](https://github.com/dimov-cz/winfstest) when run as administrator.  Without administrator privileges, cppcryptfs passes 486/492 tests.  The winftest main project page still says there are 171 tests, but there are actually 492 tests now.

The tests that cppcryptfs fails when run without administrator privileges have to do with operations on DACLs (Discretionary Access Control Lists).  cppcryptfs must be run as administrator for these operations to work.  Running without administrator privileges doesn't seem to affect the normal usage of cppcryptfs.


Build Requirements
-----
	
	Microsoft Visual Studio 2017 Community Edition, perl, nasm, and git (all free)
	OpenSSL - https://github.com/openssl/openssl (static build required)
	RapidJSON - https://github.com/miloyip/rapidjson (for parsing gocryptfs.conf)
	Dokany - https://github.com/dokan-dev/dokany

	For Dokany, you probably want to use the binary distribution from here:
		https://github.com/dokan-dev/dokany/releases
	(be sure to select "install development files" in the installer options)



There are detailed build instructions in [INSTALL.md](INSTALL.md).

cppcryptfs is currently up-to-date with Dokany 1.0.5


Use
-------

cppcryptfs doesn't require administrator privileges to run, but
if it is not running as administrator, then it won't be able
to acquire the SE_SECURITY_NAME privilege.  SE_SECURITY_NAME is
needed for some operations performed by the Windows API functions SetFileSecurity() and GetFileSecurity().

cppcryptfs seems to work without SE_SECURITY_NAME.  If you do
run into problems, then you can try running cppcryptfs as adminstrator and see if that helps.

To make a new encrypted virtual fileystem, first click the "Create" tab.

![Alt text](/screenshots/screenshot_create.png?raw=true "Create tab")

You need to find or create (you can create a directory in the directory selector in the UI) a directory to be the root of your filesystem.

If you are using normal forward mode, then this directory must be empty.

If you are using reverse mode, then it need not be empty (see the section on Reverse Mode in this document which follows this section).

It is strongly recommended that this directory reside on an NTFS filesystem.

Then you need to choose a (hopefully strong) password and repeat it.  The dialog box will accept at most 255 characters for the password.

You can choose to have your file names encryped using AES256-EME or not to encrypt the file names (plain text).

If "Long file names" is checked, then the names of files and directories can be up to 255 characters long when encrypted file names are used.  This option has no effect if plain text file names are used (plain text file names can be up to 255 characters long). See the section "File name and path length limits" near the end of this document for more information.  

You can choose between AES256-GCM or AES256-SIV (RFC 5297) for file data encryption.  The default is AES256-GCM which is recommended. GCM is about twice as fast as SIV for streaming reads and writes.  SIV was implemented in order to support reverse mode. 

Note: In the gocryptfs documentation, the SIV mode is referred to as AES-512-SIV, which is the proper name for this mode of operation. However, it is called AES256-SIV in cppcryptfs because the 512-bit SIV key is derived from the 256-bit master key (as is the case with gocryptfs).  Also, the developer of cppcryptfs doesn't want to call it AES512-SIV in the user interface because that might cause users to think that it is more secure than AES256-GCM.

If you check Reverse then you will be creating a Reverse Mode filesystem.  See the section in this document about Reverse Mode for more information.

If you wish, you can specifiy a config file.  This is the file that contains the settings for the filesystem and also the random 256-bit AES master key that is encrypted using your password.  The config file file can be kept outside the encrypted filesystem for an extra degree of security.

When you click on the "Create" button, config file will be created. It will be created as gocryptfs.conf in the root directory of the encrypted filesystem unless you specified an alternate config file.  Unless you choose to use plain text file names, a gocryptfs.diriv will also be created there.  Be sure to back up these files in case they get lost or corrupted.  You won't be able to access any of your data if something happens to gocryptfs.conf.  gocryptfs.conf will never change for the life of your filesystem unless you change the volume label (see bellow).

If you choose to give the volume a label, then the label will be encrypted in gocryptfs.conf.  The maximum volume label length is 32 characters. 

The volume label is AES256-GCM encrypted using the master key and a 128-bit random initialization vector and 8 zero bytes of auth data.  Then it is base64 encoded along with the initilization vector and saved in gocryptfs.conf.

You can right click on the mounted drive letter in File Explorer, select "Properties", and change the volume label.  However, doing so will cause cppcryptfs to re-write gocryptfs.conf when the drive is dismounted. This does entail some risk to your gocryptfs.conf.  Again, it's a good a idea to back up your gocryptfs.conf file somewhere.  

Then go to the "Mount" tab and select a drive letter and select the folder you
just created the filesystem in.  Then enter the password and click on the "Mount" button.

If you specified a custom path for the config file when you created the filesystem, then you must specify it here also.

If you specified a custom path for the config file, you must also select "reverse" if it is a reverse filesystem.  Otherwise, cppcryptfs will automatically detect if the filesytem should be mounted in forward or reverse mode.

Note:  cppcryptfs uses the path to the encrypted filesystem as a key for rembering the custom path to the config file (if there is one) and other settings like reverse and read only.  So when you select a path to mount, be sure to verify that these settings are what you wish to use this time.

![Alt text](/screenshots/screenshot_mount.png?raw=true "Mount tab")

After you mount the filesystem, you will then have a new drive letter, and you can use it like a normal drive letter and store your sensitive information there.  The data is encrypted and saved in files in the folder you specified.

If you check "Read-only", then the filesystem will be mounted read-only (write-protected).


For an explanation of how saved passwords work in cppcryptfs, please see the section on "Saved Passwords" below.

For technical details of the cryptographic design of gocryptfs, please visit
the [gocryptfs project page](https://github.com/rfjakob/gocryptfs).


When you are finished using the drive letter, go to the "Mount" tab and select the drive letter and click on "Dismount" or click "Dismount All".  The drive letter(s) will be dismounted, and the encryption keys will be erased from memory. 

You can mount as many gocryptfs filesystems as you have unused drive letters available.

Passwords and keys are locked in memory using VirtualLock(). When they are no longer needed, they are erased using SecureZeroMemory() and then unlocked.  If you never hibernate your computer, then you don't have to worry about your passwords or keys ever being written to the hard drive.

If you close the cppcryptfs window, then it will hide itself in the system tray. To exit cppcryptfs, use the Exit button on the mount page or the context menu of the system tray icon.

Settings
---------
There is also a settings tab.  

![Alt text](/screenshots/screenshot_settings.png?raw=true "Settings tab")  
*Recommended settings shown*


Changing values on the settings tab affects all filesystems that are subsequently mounted.  Any filesystems that are already mounted will not be affected.  

The current settings are stored in the Windows registry and will be used the next time a filesystem is mounted, even from the command line.

The settings tab has the following setings:

**Per-filesystem threads**

Early in cppycryptfs' development, Dokany (then version 0.9) had a problem if multiple threads were used to service requests on a single filesystem.

Therefore the number of threads per-filesystem was hard-coded to 1 in cppcryptfs.

It now appears to be safe to use more than one thread per-filesystem.  However, almost all testing and usage of cppcryptfs until now has been done with only one thread per filesystem.

Using more than one thread for each filesystem may result in improved performance.

The default number of per-filesystem threads is still 1.  Using "Dokany default" will cause Dokany to choose an appropriate number of threads.  It currently uses five threads.

**I/O buffer size (KB)**

This setting controls the maximum size of reads and writes that cppcryptfs does on the underlying fileystem.

cppcryptfs actually does I/O in multiples of the encrypted block size, which is 4,128 bytes.  So when you specify 4KB, the buffer size is really 4,128 bytes, and when you specify 1024KB, the buffer size is really 1,056,768 bytes.

Increasing the I/O buffer size may result in improved performance, especially when the underlying filesystem is a remote network filesystem.

For remote filesystems, good values to try are "Dokany default (5)" for per-filesystem threads and 64KB for I/O buffer size.

The default is the original 4KB size.  When this size is used, the code paths are almost exactly the same as they were before the I/O buffer size setting was added.

**Cache time to live**

cppcryptfs caches information about the filesystem.  If an entry in a cache is older than the time to live, then that entry
is re-validated before it is used.

Increasing the cache time to live or setting it to infinite will result in better performance.

However, if you are constantly syncing your cppcryptfs filesystem with another copy of the filesystem that is on a another machine running
under another instance of cppcryptfs or gocryptfs, then setting the time to live to too high of a value may result in errors
if the filesystem is modified on the other machine.

If you are not syncing the filesystem between two concurrently running instances of cppcryptfs or between an instance of cppcryptfs and an instance of gocryptfs, then there is no
reason to not set the cache time to live to a high value or to infinite.

**Case insensitive**

This option has effect only in forward mode and only when encrypted file names are used.  Reverse-mode filesystems with encrypted file names are always case-sensitive, and filesystems with plain text file names are always case-insensitive.

Normally, when file name encryption is used, cppcryptfs requires that files and directories be opened using the same case that was used when the files and directories were created.

If the case insensitive option is checked, then cppcryptfs will ignore the case of file and directory names, in forward mode, even when file name encryption is used.  This is how the Windows API normally operates.  Also, performance will be a little slower. 

See the section on "Case Sensitivity" for more information.

**Enable Mount Manager (Recycle Bin)**

This setting is not currently enabled when either Defaults or Recommended settings are chosen.  You must enable it separately if you wish to use it.  It has not been tested thoroughly.

This setting enables the Windows Mount Manager on the encrypted volume.  Enabling mount manager enables the recycle bin.  This setting works only if cppcryptfs is run as administrator.  If you try to mount a filesystem with this setting checked and cppcryptfs is not running as administrator, then cppcyrptfs will display a warning dialog (which can be disabled) and will not enable the mount manager.  

This setting has no effect on reverse filesystems or when filesystems are mounted read-only.

Note:  If you are syncing the encrypted files of your filesystem with Dropbox, then if you enable mount manger (recycle bin), then Dropbox will not be able to sync the files in the recycle bin because it does not have sufficient privileges.  

You should either run Dropbox as Administrator, or you should determine which encrypted folder name is the name of the recycle bin and exclude it using the selective sync feature of Dropbox.  If you are using plaintext file names, then the recycle bin will be simply "$RECYCLE.BIN". The --list command line switch, if given the (unencrypted) path to the root directory of the filesystem as an argument, can be used to find the encrypted name of the recycle bin.

e.g.


```

cppcryptfs --list=d:\


```

**Enable saved passwords**

This setting enables the saving of passwords.  Please see the section on Saved Passwords below for more information about saved passwords.

When this setting is on, the "Save password" checkbox in the mount tab will be usable.  

If the "Enable saved passwords" setting is changed from checked to unchecked, then cppcryptfs asks if all saved passwords should be deleted.

This setting is not enabled in either the Default or Recommended settings.

**Defaults and Recommended**

There are also two buttons: "Defaults" which changes all settings to the original cppcryptfs defaults, and "Recommended" which sets
the currently recommended settings.

When "Defaults" is used, then cppcryptfs will behave as it has from the beginning.  These are the safest settings which have
undergone the most testing.

When "Recommended" is used, then cppcryptfs will use settings that result in improved performance and functionality at the
expense of possibly running into new bugs.


**Reset Warnings**

Pressing the Reset Warnings button will turn back on any warning dialogs which were previously disabled by selecting "don't show this message again".


Saved Passwords
------

If the "Enable saved passwords" setting is enabled in the settings tab,  then the "Save passwords" check box on the mount tab will be usable.

When cppcryptfs saves passwords, it uses the Windows Data Protection API (DPAPI) to encrypt the passwords.  The Windows DPAPI is described here.

https://msdn.microsoft.com/en-us/library/ms995355.aspx

Data encrypted using Windows DPAPI is only as secure as the strength and security of the password used for logging into Windows.

Saved passwords are associated with the path to the root of the encrypted filesystem.  

Also, the "Save password" setting itself is assocated with the path.

To save a password, make sure the "Save password" box is checked when you mount the filesystem.

The password will be encrypted using DPAPI and saved in the Windows registry.

To mount the filesystem without typing the password, make sure "Save password" is checked, and then either select the path from the path history, in which case the password for that path (if found) will be filled in (displaying as dots) in the password field. Or, if instead of selecting the path, you type it in the path field and press the mount button without typing a password, then if the saved password for that path is found, it will be used.

The -P command line option can be used to mount filesystems from the command line using the saved password for that path.


Reverse Mode
------
In reverse mode, the source (root) directory used for the filesystem consists of unencrypted files.  When this directory is mounted, then 
the cppcryptfs drive letter provides an on-the-fly encrypted view of these files.

Reverse mode also gives a view of the config file (as gocryptfs.conf), and if encrypted file names are used, a gocryptfs.diriv file in each directory.  And if long file names are used with encrypted file names, then the special long file name files are also presented.

Reverse mode fileystems are always mounted read-only.

When you create a reverse mode fileystem, the root directory of the filesystem doesn't have to be empty (unlike in the case of creating a normal forward
mode filesystem).  cppcryptfs will create the config file 
in the root directory of the filesystem.  This is a hidden file named .gocryptfs.reverse.conf (instead of an unhidden gocryptfs.conf which is used in 
normal/forward mode).

When you go to mount a filesystem, cppcryptfs first looks for .gocryptfs.reverse.conf, and if it finds it, then it will mount the filesystem
in reverse mode.  If it doesn't find .gocryptfs.reverse.conf, then it will try to open gocryptfs.conf, and if it succeeds, then the filesysem will
mounted in forward (normal) mode.

If you specified a custom path for the config file, then you must check "reverse" to mount the filesystem in reverse mode.

If you mount a reverse filesystem and then copy the whole directory tree to some other location, you can then mount that copy (which contains encrypted files and the normal mode config file and other support files) as a forward (normal) filesystem.

Reverse mode is useful for when you want to back up a directory tree of unencrypted files, but you want the backup to be encrypted.

Reverse mode uses a deterministic AES256-SIV mode of encryption (really AES512-SIV but with the 512-bit SIV key derived from the 256-bit master key) for file data, and it also does the file name encryption deterministically.

Note: when you mount a filesystem using AES256-SIV in forward mode, any new encryption is done non-deterministcally (as is the case with gocryptfs).

Because the encryption in reverse mode is deterministic, you can use a utility like rsync to back up the encrypted files, and it will copy only the files that have changed.  Also, if your backup utility supports delta-syncing (as rsync does) when working with the unencrypted data, then it will also do delta-syncing with the encrypted data in reverse mode as long as the data is changed in-place. However, if data is inserted into a file, then a cascading change will appear in the encrypted file data from the point at which the data was inserted (actually, starting with that whole encryption block) and the data from there on will need to be copied again.

It is possible to mount a mounted reverse filesystem in forward mode.  The forward filesystem will be read-only as well.  This is useful mainly for testing.

Command Line Options
----
cppcryptfs accepts some command line options for mounting and umounting filesystems.  Currently, filesystems can be created only by using the gui.

Passwords passed through the command line are not really secure.  cppcryptfs locks and zeros its internal copies of the command line, but, for example, it does not zero the command line stored in the Windows PEB (Process Environment Block). Also, if cppcyrptfs is already running, then an invocation of cppcryptfs from the command line will cause it to pass the command line to the already running instance in the clear using a WM_COPYDATA message. It is unknown how many times the command line might be copied by Windows out of cppcryptfs' control.  So there is some chance that a password passed via the command line might end up in the paging file if a paging file is being used.

```
usage: cppcryptfs [OPTIONS]

Mounting:
  -m, --mount=PATH      mount filesystem located at PATH
  -d, --drive=D         mount to drive letter D
  -p, --password=PASS   use password PASS
  -P, --saved-password  use saved password
  -r, --readonly        mount read-only
  -c, --config=PATH     path to config file
  -s, --reverse         mount reverse filesystem

Unmounting:
  -u, --unmount=D       umount drive letter D
  -u, --umount=all      unmount all drives

Misc:
  -t, --tray            hide in system tray
  -x, --exit            exit if no drives mounted
  -l, --list            list available and mounted drive letters (with paths)
  -ld:\p, --list=d:\p   list encrypted and plaintext filenames
  -v, --version         print version
  -h, --help            display this help message

```

Note: when using the short version of the option, you should not use the equal sign between the option and its argument.  When using the long version of the option, the equal sign is optional. e.g. these will work

```
cppcryptfs -m c:\tmp\test -d k -p XYZ
cppcryptfs --mount=c:\tmp\test --drive=k --password=XYZ
cppcryptfs --mount c:\tmp\test --drive k --password XYZ

```

The --list option has an optional argument.  If there is no argument given, then
it lists the drive letters and shows the path to the root of the encrypted filesystem for mounted filesystems.  

The list command also takes a full path as an optional agument.  The path should be the unencrypted name of a file or directory including the drive letter.  If the argument is a file, then cppcryptfs will print the unencrypted file path on the left and the encrypted path on the right.   If the argument is a directory, then cppcryptfs will print the unencrypted names of the files on the left and the encrypted names on the right.

Because of the way optional arguments are handled, if you are using the short form of the list switch (-l), then you must put the path right after the -l with no space.  And if you are using the long form (--list), then you must use the "=" sign.  e.g.

```
cppcryptfs -lk:\foo

cppcryptfs --list=k:\foo

```

cppcryptfs is a Windows gui application and not a console application.  However, when started with command line options, it will try to write any error messages to the console (if any) that started it.

Unfortunately, Windows does not seem to handle piping output that is generated this way.  You cannot pipe the output of cppcryptfs through other commands like sort or redirect it to a file.

There can be only one instance of cppcryptfs running at any time.

When cppcryptfs is invoked, it checks to see if there is another instance running.  If there is, then if there are no command line options, the second instance of cppcryptfs will simply exit.  If there isn't another instance running, then it will process the command line options (if any) and  will continue running unless --exit is specified and there are no mounted drives.

If a second instance is invoked with command line options while another instance is running, the second instance will send its command line to the already-running instance using the WM_COPYDATA message.  It will block until the already-running instance has processed the command line and then exit.  Any error messages or other output that result from processing the command line will be printed in the cmd window in which the second instance was invoked.

Therefore, if you plan to use cppcryptfs in batch files, you need to start an instance in the background first.  Then you should do the other operations in the foreground so they will block until completed.

If you start "cppcryptfs --tray" in the background, then if there is already a running instance, then that instance will be told to hide itself in the system tray.  If there is not already an instance running, then you will have started cppcryptfs hidden in the system tray, running in the background. 

Here is an example Windows cmd batch file using cppcryptfs.


```
@rem ====================================================
@rem run cppcryptfs in background and give it time to start up
@rem ====================================================

start cppcryptfs.exe --tray
timeout /t 1 >nul

@rem ====================================================
@rem Mount drive U:
@rem ====================================================

cppcryptfs.exe --mount=d:\TestCppCryptFS --drive=u --password=PASSWORD --tray  --exit

@rem ====================================================
@rem Mount drive V:
@rem ====================================================

cppcryptfs.exe --mount=d:\TestCppCryptFS2 --drive=v --password=PASSWORD --tray  --exit

@rem ====================================================
@rem Run any command with the mounted drives
@rem ====================================================

copy  C:\test.txt U:\test.txt
copy  C:\test.txt V:\test.txt
```

Here is an example cygwin bash scrypt.  Note that in bash, you need to
use double-backslashes in the mount paths.


```

#!/bin/bash
# start cppcryptfs in the background and hidden in the system tray
/cygdrive/c/bin/cppcryptfs -t &
# give it time to initialize
sleep 1
# mount a filesystem and wait for the mount operation to complete
/cygdrive/c/bin/cppcryptfs --mount c:\\tmp\\test -d k -p XYZ
# do backup operation
rsync .....
# unmount all drives and exit
/cygdrive/c/bin/cppcryptfs -u all -x

```


File name and path length limits
------

If "Long file names" (the default) is specfied when creating the fileystem, or if plain text file names are used, and if the filesystem is located on NTFS, then a file or directory name can be up to 255 characters long, and a full path can be up to 32,000 characters long.

If "Long file names" is not specified and plain text file names aren't used, then the maximum length of a file or directory name is 160 characters.  But the full path limit is still 32,000 characters (assuming NTFS).

When a file name is encrypted, it is converted from UNICODE-16 to UTF-8 which, depending the language, might cause the number of characters to increase.  Then it is encrypted, which causes it to be padded by up to 16 bytes. Then it is base64 encoded, which typically results in a 33% increase in length.  The encrypted file names can therefore be signifcantly longer than the unencrypted names.

Also, the path to the directory in which the encrypted fileystem resides must be pre-pended to the path of the encrypted file names.

Older filesystems, such as FAT32, will limit the total path length to 259 characters.

It is therefore strongly recommended to use NTFS whenever possible.

A lot of Windows progams, including File Explorer that comes with Windows, have problems with long paths.  If you use encrypted file names, then you might need to use a third-party file manager that handles long file paths if you want to move the root of your encrypted filesystem.  It's a good idea to copy it and then delete the old one instead of moving it in case your file manager has problems.


Case Sensitivity
-----
The Windows API is not case-sensitive with respect to file names, but  Windows filesystems (NTFS and FAT32) preserve the case
of file names.

In Windows, if you create a file as "Foo.txt" and then try to open it as "foo.txt", it will work.

Most, but not all, software opens files using the same case that was used when the files were created.

cppcryptfs was originally always case-sensitive if encrypted file names were used. This is how gocryptfs operates.

So, if encrypted file names were used, then if a file was created as "Foo.txt", then if an attempt were made to open "foo.txt", the file would not be found.

cppcryptfs now has a "case-insensitive" setting that causes it to have case-insensitive behavior even when encrypted file names are used, but only in forward (normal) mode.

In reverse mode, file names are always case-sensitive if encrypted file names are used, regardless of the case-insensitive setting.  This is a necessary precaution because if the case of an encrypted file name is changed (for example, when backing up the filesystem), then the file name will not decrypt properly if the copy of the filesysem is subsequently mounted in forward mode.

If plain text file names are used, then file names are always case-insensitive, in both forward and reverse mode, regardless of the case-insensitive setting.


Performance
------
Below are some benchmark results.  The tests were conducted using the cygwin utilities under Windows 10 64-bit running on an Intel i5-4200U cpu with a Crucial M500 240GB ssd.  With cppcryptfs, AES256-GCM was used for encrypting file data and encrypted file names and long file names were used.

Windows Defender realtime scanning was disabled during the tests because it severely slows down cygwin tar.  It took 2m43.600s to extract linux-3.0.tar.gz on native NTFS with realtime scanning enabled.

cppcryptfs performs about the same as the mirror sample program from Dokany which doesn't do encryption.  The SSD is rated for 250 MB/sec streaming write performance.

```
                                cppcryptfs      native NTFS     Dokany mirror

Streaming Write                 168 MB/s        224 MB/s        181 MB/s
Extract linux-3.0.tar.gz        1m36.412s       0m21.291s       1m34.125s	
ls -lR linux-3.0                1m1.979s        0m2.983s        1m11.618s
Delete linux-3.0                1m28.749s       0m10.144s       1m24.677s

```

Compatibility with gocryptfs
------

cppcryptfs can mount all filesystems created by gocryptfs v0.7 and higher. Likewise, filesystems created by cppcryptfs with "long file names = off" can be mounted by gocryptfs v0.7 and higher. Filesystems with "long file names = on" can mounted by gocryptfs v0.9 and higher.

The gocryptfs [compatability matrix](https://github.com/rfjakob/gocryptfs/wiki/Compatibility) provides more details. cppcryptfs *requires* the DirIV, EMENames and GCMIV128 feature flags. It *supports* LongNames and can create filesystems with the flag on and off.

Note: cppcryptfs now keeps version number parity with gocryptfs to indicate its compatibility
with gocryptfs.  cppcryptfs is now version 1.4 and should be able to mount all filesystems created with gocryptfs 1.4.

