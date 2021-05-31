

Changelog
------------

v1.4.3.7, May 31 2021
* Close any left over open file or dirctory handles when dismounting a 
  filesystem (issue #126).
* Add setting to prompt user when dismounting a filesystem that is still
  in use (has open file or directory handles).

v1.4.3.6, Feb 7 2021
* Improve concurrency.
* Fix tab order in ui.
* Add 2MB and 4MB options for iobuffer sizes.
* Increase max number of per-fs threads to 63.
* Make better use of stack buffers.

v1.4.3.5, Dec 6 2020
* Use fast mounting only if mount point is a drive letter.  
  It doesn't make sense to poll on an existing dir, and 
  Dokany signals successful mounting fast if the mount point
  is a dir.

v1.4.3.4, Nov 28 2020
* Add "enable fast mounting" setting (enabled by default).
* Make cppcryptfs and cppcryptfsctl wait forever if the named pipe
  is busy when trying to connect to a running instance of cppcryptfs
  instead of timing out after 2 seconds.

v1.4.3.3, Nov 7 2020
* Add change password, print master key, and recover capabilities 
  to cppcryptfsctl.

v1.4.3.2, Oct 10 2020
* Fix crash in MoveFile when destination directory has corrupt or missing
  diriv file.

v1.4.3.1, Aug 29 2020
* Add capability for creating (initializing) filesystems using cppcryptfsctl.
  (please review command line options because some have changed)
  
v1.4.3.0, July 12 2020
* Add encrypt keys in memory and cache keys in memory settings.

v1.4.2.3, June 14 2020
* Fix small memory leak when files are renamed.  Renamed files also 
  weren't being protected from the race condition mentioned in 1.4.2.0.

v1.4.2.2, June 6 2020
* Fix for writing to files that are opened with only append access
  but not also (random) write access.
* Build with Dokany 1.4.0.1000.

v1.4.2.1, May 27 2020
* Fail decryption of file names that contain invalid characters in the plain 
  text.
* Use the /guard:cf compilation flag for release builds.  
* Use the /HIGHENTROPYVA linker option for 64-bit builds

v1.4.2.0, Apr 26 2020
* Fix race condition revealed by qBittorent

v1.4.1.4, Feb 6 2020
* Fix empty dialog boxes

v1.4.1.3, Jan 25 2020
* Add --csv and -D (list dirs first) options for listing encrypted
  and plaintext file names from the command line.

v1.4.1.2, Jan 18 2020
* Make sure path is directory before opening with ShellExecute.

v1.4.1.1, Jan 18 2020
* Add setting to automatically open files system upon mounting.

v1.4.1.0, Jan 11 2020
* use name pipe for passing command line to cppcryptfs and results
  back to caller.  
* Add cppcryptfsctl.

v1.4.0.29, Dec 26 2019
* Compile with Microsoft Visual Studio 2019 (instead of 2017)
  Build with Dokany 1.3.1.1000

v1.4.0.28, Oct 26 2019
* Return (NTSTATUS version of) ERROR_INVALID_NAME instead of
  (NTSTATUS version of) ERROR_FILE_NOT_FOUND when asked
  to open files with wildcard chars (* or ?) in them to fix
  globbing issue with Windows CMD.exe.

v1.4.0.27, Aug 11 2019
* Build with Dokany 1.3.0.1000
* Add option to disable named streams when creating filesystem.

v1.4.0.26, Jul 7 2019
* Add setting to enable auto-delete of desktop.ini files (issue #62)
* Show Dokany version on about tab

v1.4.0.25, Mar 17 2019
* Fix issues with TeraCopy and launching some programs from container
* Add double-click on mounted volume opens explorer feature

v1.4.0.24, Jan 13 2019
* First binary 32-bit release (was only 64-bit before)

v1.4.0.23, Jan 6 2019
* Build with Dokany 1.2.2.2000

v1.4.0.22, Oct 6 2018
* Add "never save history" option to settings
* Unmount all filesysystems when Windows session is ending

v1.4.0.21, Sep 3 2018
* Allow A: to be used for mounting.  Works since Dokany 1.2.0.1000

v1.4.0.20, Sep 1 2018
* Fix unhandled exception if started with command line options from a windows program that does not have a console and there is an error mounting the fs.

v1.4.0.19, Aug 19 2018
* Remove restriction that filesystems mounted with an empty NTFS direcory as the mount
  point must be mounted case-insensitive.  Also remove similar restriction that reverse-
  mode filesystems cannot be mounted using empty NTFS directory as the mount point (for
  the reason that reverse-mode filesystems must be case-sensitive).  This was done 
  because Dokany 1.2 fixes the gratuitous uppercasing of filenames that was happening
  when an empty NTFS directory is used as the mount point.
  
v1.4.0.18, Aug 16 2018
* Compile and link with Dokany 1.2.0.1000

v1.4.0.17, Jul 8 2018
* Fix problem with mounting encrypted filesystems from UNC paths.

v1.4.0.16, Jun 10, 2018
* Change /d2guardspecload to /Qspectre.  /Qspectre is now the preferred compiler
  flag for Spectre vulnerability mitigation according to Microsoft.
* Improve error messages if an error occurs during unmounting.
* Fix typos in messages and documentation.

v1.4.0.15, Apr 05, 2018
* Fix bug preventing changing volume name if separate config file is used.
* Integrate @mhogomchungu's RAII code to fix leak on error condition in 
  cryptconfig::write_volume_name().
* Add additional checks to verify integrity of re-written config file in 
  cryptconfig::write_volume_name().

v1.4.0.14, Mar 17, 2018
* Fix typo in settings dialog

v1.4.0.13, Mar 16, 2018
* Add properties right-click menu item and -i for showing info about
  mounted filesystems.

v1.4.0.12, Feb 19, 2018
* Use MountPointManager class to manage mounted filesystems.

v1.4.0.11, Feb 16, 2018
* Allow mounting using an empty dir mount point from command line even if that dir wasn't previously configured as a mount point in the ui.

v1.4.0.10, Feb 6, 2018
* Support use of empty directory as a mount point instead of using a drive letter.

v1.4.0.9, Jan 30, 2018
* Start using the /d2guardspecload compiler flag which Microsoft recommends for mitigating one variant of the Spectre vulnerability.

v1.4.0.8, Dec 15, 2017
* Link with Dokany 1.1.0.

v1.4.0.7,  Nov 21, 2017 
* Code reorg.

v1.4.0.6 Nov 09, 2017
* Fix findstreams on virtual files in reverse mode.

v1.4.0.5 Nov 02, 2017
 * bump version for release with sha256 code-signing signature in addtion to sha1
 
v1.4.0.4 Oct 13, 2017
* ask before deleting saved passwords

v1.4.0.3 Oct 2, 2017
* saved passwords

This changelog was unfortunately started belatedly...

