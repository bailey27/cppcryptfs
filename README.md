![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
==============

cppcryptfs
------

cppcryptfs is based on the design of [gocryptfs](https://github.com/rfjakob/gocryptfs), an encrypted overlay filesystem written in Go.

cppcryptfs is an implementation of the gocryptfs filesystem in C++ for Windows.  cppcryptfs is compatible with gocryptfs.  Filesystems created with one can generally be mounted (and synced) with the other.   Please see the statement on compatibility near the end of this document.

cppcrypts provides on-the-fly, at-rest and in-the-cloud encryption of files and file names in a virtual filesystem.  It uses the [Dokany](https://github.com/dokan-dev/dokany) driver and library to provide a virtual fileystem in user mode under Windows.


You can use cppcryptfs to create an encrypted filesystem in a folder.  The encrypted filesystem is protected with a password that you choose.  

When you use cppcryptfs to mount the encrypted filesystem by providing the password, then you have a new drive letter in Windows.  This virtual drive letter gives you an unencrypted view of your files.  The encryption and decryption are done on the fly and are transparent to applications that use the files on that virtual drive.

After you tell cppcryptfs to dismount the virtual drive letter, then there is no way to get at your unencrypted data unless the filesystem is re-mounted again using your password.  

Shutting down your computer automatically dismounts all cppcryptfs drive letters.

If the folder where the encrypted files are kept is being synced with a cloud service, then only the encrypted files with encrypted file names will be uploaded to the cloud service.

This way, neither the employees of the cloud service nor anybody who hacks into the cloud service can use your files.

Also, if someone steals your computer and the encrypted filesystem is not mounted, then the thief cannot use your files.

Because the encryption is done on a per-file basis instead of using a container file to store the data, you do not have to decide ahead of time how much encrypted storage you will need.  cppcryptfs has very minimal storage overhead, and your encrypted filesystem can grow dynamically limited only by the amount of free space on the physical drive on which the encrypted filesystem is located.

Another advantage of per-file encryption over container-based encryption is that per-file encryption syncs very quickly and efficiently with cloud-based services.


Current Status
--------------

The developer has been using cppcryptfs in forward (normal) mode for over three years and hasn't lost
any data.  At least one other person is using it.

Reverse mode has undergone only limited testing by the developer.

Binary releases signed by the developer, Bailey Brown Jr, are on the [releases page](https://github.com/bailey27/cppcryptfs/releases).


It is always prudent to keep backups of your data in case something goes wrong. 

Testing
-------  

cppcryptfs passes 506/506 tests in [winfstest](https://github.com/bailey27/winfstest) when run as administrator.  Without administrator privileges, cppcryptfs passes 500/506 tests.  This winfstest is forked from the version
used by the Dokany project.  The Dokany team added additional tests.

The tests that cppcryptfs fails when run without administrator privileges have to do with operations on DACLs (Discretionary Access Control Lists).  cppcryptfs must be run as administrator for these operations to work.  Running without administrator privileges doesn't seem to affect the normal usage of cppcryptfs.

Note: It appears that Windows 10 Version 1909 (OS Build 18363.1016) allows cppcryptfs to pass all 506 tests without having to be run as administrator.


Build Requirements
-----
	
	Microsoft Visual Studio 2019 Community Edition, perl, nasm, and git (all free)
	OpenSSL - https://github.com/openssl/openssl (static build required)
	RapidJSON - https://github.com/miloyip/rapidjson (for parsing gocryptfs.conf)
	Dokany - https://github.com/dokan-dev/dokany

	For Dokany, you probably want to use the binary distribution from here:
		https://github.com/dokan-dev/dokany/releases
	(be sure to select "install development files" in the installer options)



There are detailed build instructions in [INSTALL.md](INSTALL.md).

cppcryptfs is currently up-to-date with Dokany 1.5.0.3000


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

You need to find or create a directory to be the root of your filesystem.  You can create a directory in the directory selector in the UI.

If you are using normal (forward) mode, then this directory must be empty.

If you are using reverse mode, then the directory need not be empty (see the section on Reverse Mode in this document which follows this section).

It is strongly recommended that this directory reside on an NTFS filesystem.

Then you need to choose a (hopefully strong) password and repeat it.  The dialog box will accept at most 255 characters for the password.

The password field class treats one character as special. This character looks like a small x, but not the same. It's unicode 215 which is 0xd7 in hex.

The result is you cannot use that character in a password.

You can choose to have your file names encryped using AES256-EME or not to encrypt the file names (plain text).

If "Long file names" is checked, then the names of files and directories can be up to 255 characters long when encrypted file names are used.  This option has no effect if plain text file names are used (plain text file names can be up to 255 characters long). See the section "File name and path length limits" near the end of this document for more information.  

If a "Long name max" value that is less than 255 is selected (minimum value is 62), then cppcryptfs will limit filename length.  Even when 62 is selected, file names created will be up to 67 characters long.  This option is useful when using cloud services that have problems with filenames that are above a certain length.

You can choose between AES256-GCM or AES256-SIV (RFC 5297) for file data encryption.  The default is AES256-GCM which is recommended. GCM is about twice as fast as SIV for streaming reads and writes.  SIV was implemented in order to support reverse mode. 

Note: In the gocryptfs documentation, the SIV mode is referred to as AES-512-SIV, which is the proper name for this mode of operation. However, it is called AES256-SIV in cppcryptfs because the 512-bit SIV key is derived from the 256-bit master key (as is the case with gocryptfs).  Also, the developer of cppcryptfs doesn't want to call it AES512-SIV in the user interface because that might cause users to think that it is more secure than AES256-GCM.

If you check Reverse then you will be creating a Reverse Mode filesystem.  See the section in this document about Reverse Mode for more information.

If you wish, you can specifiy a config file.  This is the file that contains the settings for the filesystem and also the random 256-bit AES master key that is encrypted using your password.  The config file file can be kept outside the encrypted filesystem for an extra degree of security.

When you click on the "Create" button, config file will be created. It will be created as gocryptfs.conf in the root directory of the encrypted filesystem unless you specified an alternate config file.  Unless you choose to use plain text file names, a gocryptfs.diriv will also be created there.  Be sure to back up these files in case they get lost or corrupted.  You won't be able to access any of your data if something happens to gocryptfs.conf.  gocryptfs.conf will never change for the life of your filesystem unless you change the volume label (see bellow).

If you choose to give the volume a label, then the label will be encrypted in gocryptfs.conf.  The maximum volume label length is 32 characters. 

The volume label is AES256-GCM encrypted using the master key and a 128-bit random initialization vector and 8 zero bytes of auth data.  Then it is base64 encoded along with the initilization vector and saved in gocryptfs.conf.

You can right click on the mounted drive letter in File Explorer, select "Properties", and change the volume label.  However, doing so will cause cppcryptfs to re-write gocryptfs.conf when the drive is dismounted. This does entail some risk to your gocryptfs.conf.  Again, it's a good a idea to back up your gocryptfs.conf file somewhere.  

The "Disable named streams" option may be needed if the underlying filesystem (e.g. a Linux filesystem shared via Samba) does not support named streams.  cppcryptfs normally automatically detects (at mount time) if the underlying filesystem supports named streams. However, in some configurations, the underlying filesystem is reporting that it supports named streams when it actually does not.  The developer has tested with Ubuntu 16.04 Samba and does not have this problem.  This feature was added to help a user who was having this problem with a different Linux version.  Please see https://github.com/bailey27/cppcryptfs/issues/63 if you are having issues with Samba and would like to retro-actively disable named streams after creating your filesystem.

Then go to the "Mount" tab and select a drive letter and select the folder you
just created the filesystem in.  Then enter the password and click on the "Mount" button.

![Alt text](/screenshots/screenshot_mount.png?raw=true "Mount tab")

You can also right-click in the list of drive letters and select "Add Mount Point".  This will let you add an empty directory to the list of drive letters.  This empty directory, which must be on an NTFS volume, can serve as a mount point in place of a drive letter.  The added mount point will be added to the list below the drive letters.  You can also right click on an added mount point and delete it from the list.  The mount point directories you add are saved in the Windows registry.

NOTE: Though A: and B: are useable as mount points, it is not recommended to use them because mounting an encrypted filesystem to them has been known to cause problems with Windows Update.

You can also right-click on a mounted filesystem and dismount it or [view its properties.](/screenshots/screenshot_properties.png?raw=true) 

Double-clicking on a mounted volume will open a File Explorer window on it.

If you specified a custom path for the config file when you created the filesystem, then you must specify it here also.

If you specified a custom path for the config file, you must also select "reverse" if it is a reverse filesystem.  Otherwise, cppcryptfs will automatically detect if the filesytem should be mounted in forward or reverse mode.

Note:  cppcryptfs uses the path to the encrypted filesystem as a key for rembering the custom path to the config file (if there is one) and other settings like reverse and read only.  So when you select a path to mount, be sure to verify that these settings are what you wish to use this time.


After you mount the filesystem, you will then have a new drive letter, and you can use it like a normal drive letter and store your sensitive information there.  The data is encrypted and saved in files in the folder you specified.

If you check "Read-only", then the filesystem will be mounted read-only (write-protected).

For an explanation of how saved passwords work in cppcryptfs, please see the section on "Saved Passwords" below.

If you check "Auto mount" (which needs a saved password to work), then the next time you start cppcryptfs, that path will be mounted to that mount point upon startup.  You must have saved the password for that mount for this to work.  

The path will continue to automount until you manually mount it wwith "Auto mount" unchecked.

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

Using more than one thread to process requests for each filesystem may result in improved performance.

Using "Dokany default" will cause Dokany to choose an appropriate number of threads.  It currently uses five threads.

**I/O buffer size (KB)**

This setting controls the maximum size of reads and writes that cppcryptfs does on the underlying fileystem.

cppcryptfs actually does I/O in multiples of the encrypted block size, which is 4,128 bytes.  So when you specify 4KB, the buffer size is really 4,128 bytes, and when you specify 1024KB, the buffer size is really 1,056,768 bytes.

Increasing the I/O buffer size may result in improved performance, especially when the underlying filesystem is a remote network filesystem.

For remote filesystems, good values to try are "Dokany default (5)" for per-filesystem threads and 64KB for I/O buffer size.


**Cache time to live**

cppcryptfs caches information about the filesystem.  If an entry in a cache is older than the time to live, then that entry
is re-validated before it is used.

Increasing the cache time to live or setting it to infinite will result in better performance.

However, if you are constantly syncing your cppcryptfs filesystem with another copy of the filesystem that is on a another computer running
under another instance of cppcryptfs or gocryptfs, then setting the time to live to too high of a value may result in errors
if the filesystem is modified on the other computer.

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

**Never save history**

This setting prevents cppcryptfs from saving any values in the Windows registry except the values described on this page.  E.g. it will prevent the saving of paths in the history and from saving
passwords even if saved passwords has been enabled.

When this setting is checked, all values stored by cppcryptfs in the Windows registry
will be deleted except for the settings described on this page *except* for saved passwords.  However, no new passwords will be saved while this setting is in effect.

To delete saved passwords, you must un-check the "save passwords" setting.

This setting is not enabled in either the Default or Recommended settings.

**Delete desktop.ini files**

This setting was created for https://github.com/bailey27/cppcryptfs/issues/62.  It was reported that Google Drive can create hidden desktop.ini files in every directory in the source folder of encrypted files.  These files were preventing users from deleting directories from the un-encrypted side.  If the filesystem is mounted with this setting on, then cppcryptfs will automatically delete unencrypted desktop.ini files when deleting a directory.  

This setting has effect only in forward mode and only if encrypted filenames are used.

This setting is not enabled in either the Default or Recommended settings.

**Open on mounting**

If this setting is enabled, then when an encrypted volume is mounted, it will automatically be opened using the default Windows file management program which is is normally File Explorer.

This setting is not enabled in either the Default or Recommended settings.

**Encrypt Keys in Memory**

When this setting is enabled, cppcryptfs keeps the encryption keys (the primary key and any derived keys) encrypted using the Windows Data Protection API (DPAPI) when they are not needed.  The keys are encrypted using DPAPI, and they are unencrypted when needed and then the unencrypted copies are zeroed out when not needed.  See the section on "Saved Passwords" below for more information about DPAPI.

This setting reduces the chance of malicious software being able to read the unencrypted keys from cppcyrptfs's process memory.  

Also, this setting prevents the unencrypted keys from ending up on disk in the hibernation file if the system goes into hibernation.

This setting is brand new, and **any bugs in its implementation could cause data loss**.  It is recommened to use this setting only if you make frequent backups of your encrypted filesystems.

It is recommended to use "Cache Keys in Memory" (see below) with this setting. Otherwise there will be a signficant impact on performance if you do not enable "Cache Keys in Memory".

This setting is not enabled in either the Default or Recommended settings.

**Cache Keys in Memory**

This setting has no effect unless "Encrypt Keys in Memory" is enabled.

When this setting is enabled and encrypt keys in memory is also enabled, then cppcryptfs will cache the unencrypted keys between uses for up to one second.

This setting reduces the performance impact of "Encrypt Keys in Memory" to essentially zero.  Without this setting enabled, encrypt keys in memory significantly reduces performance.

When the system is about to enter standby or hibernation modes, cppcryptfs automatically disables the cache so when the system enters the low power mode, the unencrypted keys won't be in memory.  The cache is automatically re-enabled when the system wakes up.

This setting is not enabled in either the Default or Recommended settings.


**Enable fast mounting**

Previously, cppcryptfs would always wait for Dokany to call back to indicate whether or not a mount operation succeeded or failed.

Dokany was taking typically 5 seconds to call back.  However, the filesystem appeared to be mounted and available almost instantly.

When Enable fast mounting is turned on, cppcryptfs will both wait for Dokany's callback and periodically check (poll) to see
if the filesystem is mounted.  If cppcryptfs discovers that the filesystem appears to be mounted, then cppcryptfs will stop waiting on Dokany and assume the mount operation succeeded.  If this setting is disabled, then cppcryptfs will only wait for the callback from Dokany.

With this setting enabled, a successful mount operation is indicated as such on the developer's machine in about 31 milliseconds instead of 5 seconds as before.

Note:  this setting has no effect when the mount point is an empty NTFS directory and not a drive letter.  Dokany signals a successful mounting quickly if the mount point is a directory, and polling doesn't make sense in this case.

This setting is enabled by default.

**Warn if in use when dismounting**

If this setting is on, then if there are still any open files or directories 
on a mounted filesystem when the user tries to dismount the filesystem,
dismount all filesystems, or exit the program, then cppcryptfs will notify
the user and ask if it should proceed with dismounting.

If this setting is on, then the --force flag is needed on the command line when dismounting filesystems that are in use. 

This setting is not enabled in either the Default or Recommended settings.

**Deny Other Sessions**

If this setting is enabled, then encrypted volumes will be accessible only in the session that started the instance of cppcryptfs that mounted them.  Any drive letters used for mounting 
will still be visible to other sessions, but they will not be accessible to them.

The check is done only in calls to the CreateFile API (which both creates new files and directories and opens existing ones).  Denying access to other sessions 
only in CreateFile appears to be sufficient.

The scope of testing of this feature makes the developer confident that this setting makes a mounted volume safe from
access by an another ordinary logged-on user who is sharing the same computer and logged into a different session.  However, it is not certain that a determined and knowlegable attacker would not be able to find a way to circumvent this protection.  

Please see the descrition of Deny Services below for more information.

This setting is not enabled in either the Default or Recommended settings.

**Deny Services**

If this setting is enabled, then encrypted volumes will not be accessible by Windows services running in session 0.  

It is possible for Windows services running under the system account or processes created by users with the "Act as part of the operating system" user right to create access tokens and set whatever session id they want in them.  So this protection is not absolute but should prevent Windows services from accessing mounted filesystems in normal use situations.

This setting is not enabled in either the Default or Recommended settings.


**Defaults and Recommended**

These buttons restore all settings to either the default settings or
the recommended settings.

Currently, the default and recommended settings are the same.

**Reset Warnings**

Pressing the Reset Warnings button will turn back on any warning dialogs which were previously disabled by selecting "don't show this message again".


More Settings
---------
There is also a settings tab.  

![Alt text](/screenshots/screenshot_settings.png?raw=true "Settings tab")  
*Recommended settings shown*

The more settings tab has these additional settings:

**Enable Flush After Write**
A user reported that they were getting timeouts when copying lots of data to an external drive that was formatted using the exFAT filesystem.

The problem seems to be specific to exFAT.

The workaround is to enable flush after write.  When this setting is on, cppcryptfs will force Windows to write data to disk after every write operation cppcryptfs is asked to do.  

This option reduces write performance noticeably. For copying large files, it's about 50% worse.  For lots of small files, it's much worse than that.

The setting is on if any of the condidtions are true, so to enable it always, one could check both the "NTFS" and "Not NTFS" boxes.


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
cppcryptfs accepts some command line options for mounting and unmounting filesystems.  Currently, filesystems can be created only by using the gui.

There can be only one main instance of cppcryptfs running.  If no other instance of cppcryptfs is running, then cppcryptfs processes any command line arguments and then continues
to run.  If there is already another instance of cppcryptfs running, then cppcryptfs will send its command line arguments to the main, already-running, instance.  If run from a
console window, it will print any output from processing the command line to the console. If not run from a console, it will display the output in a message box.

There is also a companion program, cppcryptfsctl, that can be used to send commands to an already-running cppcryptfs.  cppcryptfsctl is a console program.  The
advantage of using it is that it sets ERRORLEVEL so this can be tested in batch scripts.  Also, it is possible to redirect the output of cppcryptfsctl to a file
or pipe it to another program like grep of findstr.  cppcryptfs does not set ERRORLEVEL, and its output cannot be redirected.

cppcryptfsctl sets ERRORLEVEL to 0 on success, to 1 if an error occurs, and to 2 if it cannot connect which implies  that cppcryptfs isn't running.

Passwords passed through the command line are not really secure.  cppcryptfs locks and zeros its internal copies of the command line, but, for example, it does not zero the command line stored in the Windows PEB (Process Environment Block). Also, if cppcyrptfs is already running, then an invocation of cppcryptfs (or cppcryptfsctl) from the command line will cause it to pass the command line to the already running instance. It tries to do this in a fairly secure way.  It communicates with the running instance using a local Windows named pipe. If the program running on either side of the pipe is signed, then it verifies that the program on the other end of the pipe is also running from a signed executable and that the common name on both signatures are the same.  However, it is unknown how many times the command line might be copied by Windows out of cppcryptfs' control.  So there is some chance that a password passed via the command line might end up in the paging file if a paging file is being used.

The name of the named pipe is decorated with the username and domain name of the user who started cppcryptfs.  Therefore cppcryptfs/cppcryptfsctl can be used to 
communicate only with an instance of cppcryptfs started by the same user.

```

Usage: cppcryptfs/cppcryptfsctl [OPTIONS]

Mounting:
  -m, --mount=PATH            mount filesystem located at PATH
  -d, --drive=D               mount to drive letter D or empty dir DIR
  -p, --password=PASS         use password PASS
  -P, --saved-password        use saved password
  -r, --readonly              mount read-only
  -c, --config=PATH           path to config file for init/mount
  -s, --reverse               init/mount reverse fs (implies siv for init)
  --deny-other-sessions [1|0] enable/disable deny other sessions from accessing
  --deny-services [1|0]       enable/disable deny services from accessing

Unmounting:
  -u, --unmount=D             unmount drive letter D or dir DIR
  -u, --unmount=all           unmount all drives
  -f, --force                 force unmounting if in use

Misc:
  -t, --tray                  hide in system tray
  -x, --exit                  exit if no drives mounted
  -l, --list                  list avail drive letters and mounted fs 
  -ld:\p, --list=d:\p         list plaintext and encrypted filenames
  -C, --csv                   file list is comma-delimited
  -D, --dir                   file list dirs first and w/ trailing \"\\\"
  -i, --info=D                show information about mounted filesystem
  -v, --version               print ver (use --init -v for cppcryptfsctl ver)
  -h, --help                  display this help message

Initializing (cppcryptfsctl only):
  -I, --init=PATH             Initialize encrypted filesystem located at PATH
  -V, --volumename=NAME       specify volume name for filesystem
  -T, --plaintext             use plaintext filenames (default is AES256-EME)
  -S, --siv                   use AES256-SIV for data encr (default is GCM)
  -L, --longnames [1|0]       enable/disable LFNs. defaults to enabled (1)
  -b, --streams   [1|0]       enable/disable streams. defaults to enabled (1)
  --longnamemax   N			  limit filenames to at most N characters

Recovery/Maintenance (cppcryptfsctl only):
  --changepassword=PATH       Change password used to protect master key
  --printmasterkey=PATH       Print master key in human-readable format
  --recover=PATH              Prompt for master key and new password to recover

```

Only cppcryptfsctl can create a filesystem from the command line(--init).  To create a filesystem with cppcryptfs you have to use the GUI.  

When creating/initializing a filesystem, cppcryptfsctl will prompt for the password and repeat password without echo if run interactively. If its standard input is redirected, then it will read the password from standard input without prompting.

To get the version of cppcryptfsctl, you must specify initialize and -v.  e.g. cppcryptfsctl -I -v, otherwise it will attempt to get and print the version of a running instance of cppcryptfs.

Some options are common to both initializing and mounting (--config and --reverse).

Note: when using the short version of the option, you should not use the equal sign between the option and its argument.  When using the long version of the option, the equal sign is optional. e.g. these will work

Also, if you intend to mount a volume to a drive letter, then you should not include a \\ character in the argument to the drive option.  e.g. if you want to mount to drive "r:" use "-dr:" and not "-dr:\\".


```
cppcryptfs -m c:\tmp\test -d k -p XYZ
cppcryptfs --mount=c:\tmp\test --drive=k --password=XYZ
cppcryptfs --mount c:\tmp\test --drive k --password XYZ

```

The --list option has an optional argument.  If there is no argument given, then
it lists the drive letters and shows the path to the root of the encrypted filesystem for mounted filesystems.  

The list command also takes a full path as an optional argument.  The path should be the unencrypted name of a file or directory including the drive letter.  If the argument is a file, then cppcryptfs will print the unencrypted file path on the left and the encrypted path on the right.   If the argument is a directory, then cppcryptfs will print the unencrypted names of the files on the left and the encrypted names on the right.

Because of the way optional arguments are handled, if you are using the short form of the list switch (-l), then you must put the path right after the -l with no space.  And if you are using the long form (--list), then you must use the "=" sign.  e.g.

```
cppcryptfs -lk:\foo

cppcryptfs --list=k:\foo

```

There can be only one instance of cppcryptfs running at any time.

When cppcryptfs is invoked, it checks to see if there is another instance running.  If there is, then if there are no command line options, the second instance of cppcryptfs will simply exit.  If there isn't another instance running, then it will process the command line options (if any) and  will continue running unless --exit is specified and there are no mounted drives.

Therefore, if you plan to use cppcryptfs or cppcryptfsctl in batch files, you need to start an instance in the background first.  Then you should do the other operations in the foreground so they will block until completed.

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

Change Password
------
cppcryptfsctl has the ability to change the password that protects the master key in the config file (normally gocryptfs.conf or .gocryptfs.reverse.conf).

This feature is mainly for people who just want to use a different password.  It is not a good solution for a compromised password.

All changing the password does is change the password used to mount the filesystem.  It does not change the encryption key used to encrypt the data.  This is because the key that is used to encrypt the data is encrypted using a key derived from the password and stored in the config file.  So all the password is used for is to unencrypt the actual encryption key.

Therefore, if somebody has your password and a copy of your old config file, then they would still be able to decrypt the data and any data you add or change
after changing the password. 

If you think your password has been compromised, and if you think somebody might already have your config file, then the best thing to do is to create a new
filesystem with a new password, mount it, mount the old filesystem, and copy your data from the unencrypted view of the old filesytem to the unencrypted 
view of the new filesystem.

Recovery of Lost Password
-----------
Recovering from a lost password is possible only if you have printed and saved the
unencrypted master key.

If you run:

cppcryptfsctl --printmasterkey PATH (path to encrypted filesystem dir or config file)

It will print the unencrypted master key in human-readable form.  For example, you could print it and save it in a locked drawer.

If you forget your password, you can run

cppcryptfsctl --recover PATH 

It will prompt for you to enter the master key, and then it will prompt for you to enter the new password and confirm the new password.

This operation overrwrites the master key in the target config file.  It makes a backup of the config file before doing this. The backup is named by appending .bak to the name of the config file. If the .bak file already exists, it asks for you to delete the existing .bak file or move it out of the way.


Recovery of Lost or Corrupted Config File
-----------
Recovery of a lost or corrupted config file is possible only if you have the unencrypted master key.

cppcryptfsctl --printmasterkey PATH (path to encrypted filesystem dir or config file)

This will print the unencrypted master key in human-readable form.  If you did this and saved the key, then you can use it to recover
from a lost or corrupted config file.

The procedure is to do this (assuming you have printed the master key and saved it before recovery was necessary):

1. You will need to create a new filesystem, using the same parameters other than paths (e.g. data encryption method, filename encryption method, long
filenames, etc.) that you used when you created the filesystem that you are trying to recover.  

It doesn't matter what password you use.

2. use cppcryptfsctl --recover PATH to put the master key from the old filesystem in that config file.

This will replace the master key in that config file with the one you entered.  It will be encrypted with the new password you choose.

3. Try mounting the old filesystem specifying the path to the new config file and see if works (make sure you can read data from it).

4. If it works, then you can place the config file you recovered to in the root of your encrypted filesystem if you wish.

The only catch here is that if you have a filesystem created with gocryptfs or cppcryptfs versions prior to 1.3 
(released in April/May 2017), then you will have problems with HKDF and Raw64.  These are now defaults, and 
there is no way to create a config file without them.

So if you have an old filesystem you are recovering, and it's not working,  then try editing
the config file you created to recover to and remove the lines that have 

```
        "HKDF",
        "Raw64",
```

And see if that works.        


File name and path length limits
------

If "Long file names" (the default) is specfied when creating the fileystem, or if plain text file names are used, and if the underlying filesystem is reasonably modern (e.g. NTFS/exFAT/FAT32), then a file or directory name can be up to 255 characters long, and a full path can be approximately 32,000 characters long.

If "Long file names" is not specified and plain text file names aren't used, then the maximum length of a file or directory name is 160 characters.  But the full path limit is still approximately 32,000 characters (assuming NTFS/exFAT/FAT32).

When a file name is encrypted, it is converted from UNICODE-16 to UTF-8 which, depending the language, might cause the number of characters to increase.  Then it is encrypted, which causes it to be padded by up to 16 bytes. Then it is base64 encoded, which typically results in a 33% increase in length.  The encrypted file names can therefore be signifcantly longer than the unencrypted names.

Also, the path to the directory in which the encrypted fileystem resides must be pre-pended to the path of the encrypted file names.

Older filesystems, such as FAT16, will limit the total path length to 259 characters.

It is therefore strongly recommended to use a modern file system like NTFS, exFAT, or FAT32 whenever possible.

A lot of Windows progams, including File Explorer that comes with Windows, have problems with paths longer than the old 259 character limit, regardless of which underlying filesystem is used.  If you use encrypted file names, then you might need to use a third-party file manager that handles long file paths if you want to move the root of your encrypted filesystem.  It's a good idea to copy it and then delete the old one instead of moving it in case your file manager has problems.


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

The above benchmarks were run a long time ago.  The creator of gocryptfs has published similar benchmarks more recently comparing cppcryptfs to other cryptographic filesystems on Windows.  

https://nuetzlich.net/gocryptfs/comparison/#performance-on-windows

Some of the results are faster but most are slower than the above benchmarks.
This could be explained by Windows Defender realtime protection being
active during the tests.  All cryptographic filesystems tested
seem to have been affected in the same way.

Compatibility with gocryptfs
------

cppcryptfs can mount all filesystems created by gocryptfs v0.7 and higher. Likewise, filesystems created by cppcryptfs with "long file names = off" can be mounted by gocryptfs v0.7 and higher. Filesystems with "long file names = on" can mounted by gocryptfs v0.9 and higher.

The gocryptfs [compatability matrix](https://github.com/rfjakob/gocryptfs/wiki/Compatibility) provides more details. cppcryptfs *requires* the DirIV, EMENames (if encrypted file names and not plaintext file names are used), and GCMIV128 feature flags. It *supports* LongNames and can create filesystems with the flag on and off.

Note: cppcryptfs now keeps version number parity with gocryptfs to indicate its compatibility
with gocryptfs.  cppcryptfs is now version 1.4 and should be able to mount all filesystems created with gocryptfs 1.4.


