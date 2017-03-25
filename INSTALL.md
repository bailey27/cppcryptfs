cppcryptfs Build and Installation
--------------

You will need the following software to build cppcryptfs:

Microsoft Visual Studio, perl, and git.

The free Microsoft Visual Studio 2015 Community Edition is recommended

https://www.visualstudio.com/vs/community/

You need to install Visual Studio in such a way that you can compile C++ applications with support for Microsoft Foundation Classes (MFC).  

The professional edition should be fine if you already have that. The "Express" edition will not work due to its lack of support for MFC.

In order to build OpenSSL, you will need perl and nasm.  

For Perl, the OpenSSL documentation recommends using the free ActiveState ActivePerl.

http://www.activestate.com/activeperl/downloads

nasm (Netwide Assembler) is available from here http://www.nasm.us/

For git, the git that comes with cygwin works well.  git is not selected in the cygwin install by default.  You will need to select it.

https://www.cygwin.com/

You don't need git if you download the source zip files from github
and unzip them.

These instructions assume that you are using git.

Whether or not you are using git, everything will go easier if you put everything in C:\git, e.g.

```
c:
cd \
mkdir git
cd git
git clone ... (or extract zip here)
```

Dokany
------
Unless you want to develop or debug Dokany, you should just install the Dokany release binaries from here.

https://github.com/dokan-dev/dokany/releases

Using DokanSetup_redist.exe is probably the safest bet. Be sure to go into the installer options and select "install development files".

OpenSSL
---------
cppcryptfs uses OpenSSL for doing the actual encrypting and decrypting of data.

Please refer to the "INSTALL" file from the OpenSSL distribution in case these instructions don't work.

First, clone OpenSSL.

```
c:
cd \git
git clone https://github.com/openssl/openssl.git
cd openssl
```

Then run the batch file that comes with Visual Studio to set up the environment variables for compiling from the command line, e.g.

```
"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x64
```

Use "x86" in place of "x64" if you are doing a 32-bit build.

If you've installed the Windows SDK and/or the DDK, then you might need  to set these include 
and lib paths.  If you are building with the Dokany binary release libs and headers, then you shouldn't
need to install the Windows SDK or DDK.  They are needed only if you are building Dokany from source.

So these "set" commands probably won't be needed, but here they are just in case.

```
set include=C:\Program Files (x86)\Windows Kits\10\Include\10.0.10586.0\um;%include%
set include=C:\Program Files (x86)\Windows Kits\10\Include\10.0.10586.0\shared;%include%
set include=C:\Program Files (x86)\Windows Kits\10\Include\10.0.10586.0\ucrt;%include%

set lib=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.10586.0\um\x64;%lib%
set lib=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.10586.0\ucrt\x64;%lib%
```

Use "x86" in place of "x64" in the above lib vars if you are doing a 32-bit build.

Then run (ActiveState) perl to configure OpenSSL for a Visual Studio AMD64/X86_64 static build.  
Use "VC-WIN32" instead of  "VC-WIN64A" if you're doing a 32-bit build

```
perl Configure VC-WIN64A no-shared
```

Then run "nmake" to build OpenSSL.

Then run "nmake install" to install it.  nmake install must be run from an elevated (adminstrator) command prompt in order for it to work.

There might be some errors about installing the OpenSSL documentation.  They won't affect your ability to build cppcryptfs.

rapidjson
------

rapidjson is used for parsing the config file gocryptfs.conf.  It consists of only header files, so there is no need to build it separately.

```
c:
cd \git
git clone https://github.com/miloyip/rapidjson.git
```

cppcryptfs
----------
First, clone cppcryptfs.

```
c:
cd \git
git clone https://github.com/bailey27/cppcryptfs.git
```

Then go to c:\\git\\cppcryptfs in Windows Explorer and double-click on cppcryptfs.sln.  This will load the project into Visual Studio.

Then change the build target to "Release" and "x64" to do a release 64-bit build, and then do Build -> Build Solution.

There is no installation program for cppcryptfs.  You will need to copy cppcryptfs.exe (e.g. C:\\git\\cppcryptfs\\x64\\Release\\cppcryptfs.exe) to some directory in your path.


A 32-bit build should work.  However, it has not been tested in a while.

Whenever Dokany releases a new version, they install their header files in a directory that has the Dokany version number in its name.  Therefore, if cppcryptfs gets behind the current Dokany version, even a minor one, then you will need to change the include paths in the cppcryptfs Visual Studio project.  To do this, in Visual Studio, right click on "cppcryptfs" in the Solution Explorer pane.  Then select Properties and go to "C/C++" then "General".  Then edit "Additional Include Directories" so that the current Dokany version is there in the path for the Dokany header files.  Make sure you have selected the Configuration and Platform that you are actually building for when you do this.

Here is a link to a screenshot showing this: [Visual Studio include paths screenshot](/screenshots/include_paths.png?raw=true")


The default (master) branch of cppcryptfs is for building with the Dokany binary release.  

If you would like to build cppcryptfs with the current Dokany source, then after you clone cppcryptfs you need to switch to the current_dokany branch of cppcryptfs. 



		git checkout current_dokany
