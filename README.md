![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
==============

This software is based on the design of gocryptfs.

[gocryptfs](https://github.com/rfjakob/gocryptfs)
An encrypted overlay filesystem written in Go.

cppcryptfs is an implementation of gocryptfs in C++ for Windows.

It uses the the Dokany driver and library to provide a virtual fileystem in user mode under Windows.
[dokany](https://github.com/dokan-dev/dokany)

Current Status
--------------

cppcryptfs is best described as currentyl pre-alpha, or more accurately, as experimental.


Testing
-------

It seems to work.  It passesss 169/171 of the tests in winfstest.
[winfstest](https://github.com/dimov-cz/winfstest)

The two failures are due to file sharing issues.  Due to the nature of how gocryptfs is implemented (namely, that it is impossible to write to a file unless you are able to also read from it), it is probably impossible to pass these two tests.  And it is the opinion of the developer that these failures probably don't matter.

Build Requirements
-------
	
	Microsoft Visual Studio 15 Community Edition
	[openssl](https://github.com/openssl/openssl)
	[dokany](https://github.com/dokan-dev/dokany)
	[rapidjson]https://github.com/miloyip/rapidjson	

	For Dokany, you probably want to get the binary distribution and install it from here (https://github.com/dokan-dev/dokany/releases)

	The version currently used with cppcryptfs is Dokany 1.0.0-RC3

Use
-------

To use it, you need to find or create (in the UI) an empty directory.

Click the "Create" tab to do this.

Then you need to choose a (hopefully strong) password and repeat it.

When you click on "Create", a gocyrptfs.conf file will be created in the directory, as will a gocryptfs.diriv.  Be sure to backup these files in case they get lost or corrupted.  You won't be able to access any of your data if something happens to gocryptfs.conf.  It will never change for the life of your filesystem.

Then go to the "Mount" tab and select a drive letter and select tye folder you
just created the filesystem in.  Then enter the password and click on "Mount".

Your will then have a new drive letter, and you can store your sensitive information there an use it like a normal drive lettere.  The data is actually saved
in files in the folder you specified.

The files are encrypted with AES256-GCM, and the filenames are encrypted using
AES246-EME (by default).  You can choose to use plaintext filenames or even
AES256-CBC if you wish.

