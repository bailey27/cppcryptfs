cppcryptfs Build and Installation
--------------

You will need the following software, all available for free, to build cppcryptfs:

Microsoft Visual Studio, perl, nasm and git. git is optional.

The free Microsoft Visual Studio 2017 Community Edition is recommended

https://www.visualstudio.com/vs/community/

The professional edition or the enterprise edition should be fine if you already have either of those.

You need to install Visual Studio in such a way that you can compile C++ applications with support for Microsoft Foundation Classes (MFC).  

When installing Visual Studio 2017, select "Desktop development with C++", and be sure to also check "MFC and ATL support (x86 and x64)".

Here is a screenshot that shows what to select when installing Visual Studio.

[Visual Studio install screenshot](/screenshots/visual_studio_2017_install.png?raw=true") 

In order to build OpenSSL, you will need perl and nasm.  

For Perl, the OpenSSL documentation recommends using the free ActiveState ActivePerl.

http://www.activestate.com/activeperl/downloads

nasm (The Netwide Assembler) is available from here http://www.nasm.us/

Git is available from https://git-scm.com/downloads

The git that comes with cygwin also works.  

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

Please refer to the "INSTALL" file from the OpenSSL distribution if these instructions don't work.

After installing nasm, git and ActiveState perl, clone OpenSSL.

```
c:
cd \git
git clone https://github.com/openssl/openssl.git
cd openssl
```

Then run the batch file that comes with Visual Studio to set up the environment variables for compiling from the command line.

```
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64

```

Use "x86" in place of "amd64" if you are doing a 32-bit build.

This vcvarsall.bat file from Visual Studio 2017 does not work in a TCC LE command prompt.  You must use a normal Windows cmd.exe command prompt.


Then run (ActiveState) perl to configure OpenSSL for a Visual Studio AMD64/X86_64 static build.  
Use "VC-WIN32" instead of  "VC-WIN64A" if you're doing a 32-bit build

```
perl Configure VC-WIN64A no-shared
```

Then run "nmake" to build OpenSSL.

Then run "nmake install" to install it.  nmake install must be run from an elevated (adminstrator) command prompt in order for it to work.  If you built openssl from a non-elevated command prompt, then start an elevated one and be sure to invoke vcvarsall.bat as shown above again in the elevated command prompt before running nmake install in it.

There might be errors about installing the OpenSSL documentation.  They won't affect your ability to build cppcryptfs.

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

Then change the build configuration to "Release" and the target platform to"x64".

Here is a screenshot that shows where to set the build configuration and target platform (see the red underlines).

[Visual Studio build configuration and target platform screenshot](/screenshots/build_config_and_target.png?raw=true") 

Then do Build -> Build Solution, or just press the F7 key.

There is no installation program for cppcryptfs.  You will need to copy cppcryptfs.exe (e.g. C:\\git\\cppcryptfs\\x64\\Release\\cppcryptfs.exe) to some directory in your path.


A 32-bit build should work.  However, it has not been tested in a while.

Whenever Dokany releases a new version, they install their header and library files in a path that has the Dokany version number in its name.  Therefore, if cppcryptfs gets behind the current Dokany version, even a minor one, then you will need to change the include and library paths in the cppcryptfs Visual Studio project.  

To change the include path in Visual Studio, right click on "cppcryptfs" in the Solution Explorer pane.  Then select "Properties" and go to "C/C++" then "General".  Then edit "Additional Include Directories" so that the current Dokany version is there in the path for the Dokany header files.  Make sure you have selected the Configuration and Platform that you are actually building for when you do this.

To change the library path, go to "Linker" and then "Input" and edit "Additional Dependencies".

Here are links to screenshots: 

[Visual Studio include paths screenshot](/screenshots/include_paths.png?raw=true") 

[Visual Studio library paths screenshot](/screenshots/library_paths.png?raw=true") 

The screenshots were made with Visual Studio 2015 when Dokany 1.0.2 was the Dokany version that cppcryptfs was expecting to use, but Dokany 1.0.3 was installed.  The UI for changing these things in Visual Studio 2017 is the same.


