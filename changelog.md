

Changelog
------------
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

This changelong was unfortunately was started belatedly...

