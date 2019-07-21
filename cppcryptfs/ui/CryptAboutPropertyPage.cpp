/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


// CryptAboutPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CryptAboutPropertyPage.h"
#include "afxdialogex.h"
#include <dokan/cryptdokan.h>
#include <string>
#include "util/util.h"
#include "crypt/aes.h"
#include "openssl/crypto.h"


// CCryptAboutPropertyPage dialog

IMPLEMENT_DYNAMIC(CCryptAboutPropertyPage, CCryptPropertyPage)

CCryptAboutPropertyPage::CCryptAboutPropertyPage()
	: CCryptPropertyPage(IDD_ABOUTBOX)
{

}

CCryptAboutPropertyPage::~CCryptAboutPropertyPage()
{
}

void CCryptAboutPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CCryptPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCryptAboutPropertyPage, CCryptPropertyPage)
	ON_EN_CHANGE(IDC_INFO, &CCryptAboutPropertyPage::OnEnChangeInfo)
	ON_EN_SETFOCUS(IDC_INFO, &CCryptAboutPropertyPage::OnSetfocusInfo)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_COMPONENTS_LIST, &CCryptAboutPropertyPage::OnItemchangedComponentsList)
END_MESSAGE_MAP()



static const WCHAR * components[] = {
	L"cppcryptfs - Copyright (C) 2016-2019 Bailey Brown. All Rights Reserved.",
	L"OpenSSL - Copyright (c) 1998-2018 The OpenSSL Project.  All rights reserved.",
	L"RapidJSON - Copyright (C) 2015 THL A29 Limited, a Tencent company, and Milo Yip. All rights reserved.",
	L"Dokany (mirror) - Copyright (C) 2015 - 2018 Adrien J., Maxime C.; Copyright (C) 2007 - 2011 Hiroki Asakawa",
	L"Dokany (library) - Copyright (C) 2015 - 2018 Adrien J., Maxime C.; Copyright (C) 2007 - 2011 Hiroki Asakawa",
	L"100% free Secure Edit control MFC class - Copyright (c) 2003 Dominik Reichl",
	L"getopt_port - Copyright (c) 2012-2017, Kim Grasman <kim.grasman@gmail.com>. All rights reserved.",
	L"aes-siv - Copyright (c) 2015 ARKconcepts / Sasha Kotlyar",
	NULL
};

static const WCHAR *licenses[] = {

	// cppcryptfs
	L"cppcryptfs - Copyright (C) 2016-2019 Bailey Brown. All rights reserved.\r\n\r\n"
	L"project url: github.com/bailey27/cppcryptfs\r\n\r\n"
	L"cppcryptfs is a user-mode cryptographic virtual overlay filesystem\r\n\r\n"
	L"cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)\r\n\r\n"
	L"cppcryptfs links with and incorporates source code from several open source projects.\r\n\r\n"
	L"All incorporated sources use the MIT license or other permissive open source licenses.\r\n\r\n"
	L"All statically linked libraries use a permissive open source license.\r\n"
	L"\r\n"
	L"Some libraries which are linked with dynamically use the GNU LGPL.\r\n"
	L"\r\n"
	L"cppcryptfs itself uses an MIT license which is as follows:\r\n"
	L"\r\n"
	L"The MIT License (MIT)\r\n"
	L"\r\n"
	L"Permission is hereby granted, free of charge, to any person obtaining a copy\r\n"
	L"of this software and associated documentation files (the \"Software\"), to deal\r\n"
	L"in the Software without restriction, including without limitation the rights\r\n"
	L"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\r\n"
	L"copies of the Software, and to permit persons to whom the Software is\r\n"
	L"furnished to do so, subject to the following conditions:\r\n"
	L"\r\n"
	L"The above copyright notice and this permission notice shall be included in\r\n"
	L"all copies or substantial portions of the Software.\r\n"
	L"\r\n"
	L"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\r\n"
	L"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\r\n"
	L"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\r\n"
	L"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\r\n"
	L"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\r\n"
	L"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\r\n"
	L"THE SOFTWARE.\r\n"
	L"\r\n",

	// openssl

	L"poject url: github.com/openssl/openssl\r\n\r\n"
	L"cppcryptfs usage: statically linked library\r\n\r\n"
	L"OpenSSL copyright and license:\r\n\r\n"
	L" LICENSE ISSUES\r\n"
	L"  ==============\r\n"
	L"\r\n"
	L"  The OpenSSL toolkit stays under a dual license, i.e. both the conditions of\r\n"
	L"  the OpenSSL License and the original SSLeay license apply to the toolkit.\r\n"
	L"  See below for the actual license texts.\r\n"
	L"\r\n"
	L"  OpenSSL License\r\n"
	L"  ---------------\r\n"
	L"\r\n"
	L"/* ====================================================================\r\n"
	L" * Copyright (c) 1998-2018 The OpenSSL Project.  All rights reserved.\r\n"
	L" *\r\n"
	L" * Redistribution and use in source and binary forms, with or without\r\n"
	L" * modification, are permitted provided that the following conditions\r\n"
	L" * are met:\r\n"
	L" *\r\n"
	L" * 1. Redistributions of source code must retain the above copyright\r\n"
	L" *    notice, this list of conditions and the following disclaimer. \r\n"
	L" *\r\n"
	L" * 2. Redistributions in binary form must reproduce the above copyright\r\n"
	L" *    notice, this list of conditions and the following disclaimer in\r\n"
	L" *    the documentation and/or other materials provided with the\r\n"
	L" *    distribution.\r\n"
	L" *\r\n"
	L" * 3. All advertising materials mentioning features or use of this\r\n"
	L" *    software must display the following acknowledgment:\r\n"
	L" *    \"This product includes software developed by the OpenSSL Project\r\n"
	L" *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)\"\r\n"
	L" *\r\n"
	L" * 4. The names \"OpenSSL Toolkit\" and \"OpenSSL Project\" must not be used to\r\n"
	L" *    endorse or promote products derived from this software without\r\n"
	L" *    prior written permission. For written permission, please contact\r\n"
	L" *    openssl-core@openssl.org.\r\n"
	L" *\r\n"
	L" * 5. Products derived from this software may not be called \"OpenSSL\"\r\n"
	L" *    nor may \"OpenSSL\" appear in their names without prior written\r\n"
	L" *    permission of the OpenSSL Project.\r\n"
	L" *\r\n"
	L" * 6. Redistributions of any form whatsoever must retain the following\r\n"
	L" *    acknowledgment:\r\n"
	L" *    \"This product includes software developed by the OpenSSL Project\r\n"
	L" *    for use in the OpenSSL Toolkit (http://www.openssl.org/)\"\r\n"
	L" *\r\n"
	L" * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY\r\n"
	L" * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\r\n"
	L" * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\r\n"
	L" * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR\r\n"
	L" * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\r\n"
	L" * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\r\n"
	L" * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\r\n"
	L" * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\r\n"
	L" * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\r\n"
	L" * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\r\n"
	L" * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\r\n"
	L" * OF THE POSSIBILITY OF SUCH DAMAGE.\r\n"
	L" * ====================================================================\r\n"
	L" *\r\n"
	L" * This product includes cryptographic software written by Eric Young\r\n"
	L" * (eay@cryptsoft.com).  This product includes software written by Tim\r\n"
	L" * Hudson (tjh@cryptsoft.com).\r\n"
	L" *\r\n"
	L" */\r\n"
	L"\r\n"
	L" Original SSLeay License\r\n"
	L" -----------------------\r\n"
	L"\r\n"
	L"/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)\r\n"
	L" * All rights reserved.\r\n"
	L" *\r\n"
	L" * This package is an SSL implementation written\r\n"
	L" * by Eric Young (eay@cryptsoft.com).\r\n"
	L" * The implementation was written so as to conform with Netscapes SSL.\r\n"
	L" * \r\n"
	L" * This library is free for commercial and non-commercial use as long as\r\n"
	L" * the following conditions are aheared to.  The following conditions\r\n"
	L" * apply to all code found in this distribution, be it the RC4, RSA,\r\n"
	L" * lhash, DES, etc., code; not just the SSL code.  The SSL documentation\r\n"
	L" * included with this distribution is covered by the same copyright terms\r\n"
	L" * except that the holder is Tim Hudson (tjh@cryptsoft.com).\r\n"
	L" * \r\n"
	L" * Copyright remains Eric Young's, and as such any Copyright notices in\r\n"
	L" * the code are not to be removed.\r\n"
	L" * If this package is used in a product, Eric Young should be given attribution\r\n"
	L" * as the author of the parts of the library used.\r\n"
	L" * This can be in the form of a textual message at program startup or\r\n"
	L" * in documentation (online or textual) provided with the package.\r\n"
	L" * \r\n"
	L" * Redistribution and use in source and binary forms, with or without\r\n"
	L" * modification, are permitted provided that the following conditions\r\n"
	L" * are met:\r\n"
	L" * 1. Redistributions of source code must retain the copyright\r\n"
	L" *    notice, this list of conditions and the following disclaimer.\r\n"
	L" * 2. Redistributions in binary form must reproduce the above copyright\r\n"
	L" *    notice, this list of conditions and the following disclaimer in the\r\n"
	L" *    documentation and/or other materials provided with the distribution.\r\n"
	L" * 3. All advertising materials mentioning features or use of this software\r\n"
	L" *    must display the following acknowledgement:\r\n"
	L" *   \"This product includes cryptographic software written by\r\n"
	L" *     Eric Young (eay@cryptsoft.com)\"\r\n"
	L" *    The word 'cryptographic' can be left out if the rouines from the library\r\n"
	L" *    being used are not cryptographic related :-).\r\n"
	L" * 4. If you include any Windows specific code (or a derivative thereof) from \r\n"
	L" *    the apps directory (application code) you must include an acknowledgement:\r\n"
	L" *    \"This product includes software written by Tim Hudson (tjh@cryptsoft.com)\"\r\n"
	L" * \r\n"
	L" * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND\r\n"
	L" * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\r\n"
	L" * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\r\n"
	L" * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE\r\n"
	L" * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\r\n"
	L" * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS\r\n"
	L" * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\r\n"
	L" * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT\r\n"
	L" * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY\r\n"
	L" * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF\r\n"
	L" * SUCH DAMAGE.\r\n"
	L" * \r\n"
	L" * The licence and distribution terms for any publically available version or\r\n"
	L" * derivative of this code cannot be changed.  i.e. this code cannot simply be\r\n"
	L" * copied and put under another distribution licence\r\n"
	L" * [including the GNU Public Licence.]\r\n"
	L" */\r\n",

	// rapidjson
	L"project url: github.com/miloyip/rapidjson\r\n\r\n"
	L"cppcryptfs usage: included header files\r\n\r\n"
	L"RapidJSON copyright and license:\r\n\r\n"
	L"Tencent is pleased to support the open source community by making RapidJSON available. \r\n"
	L" \r\n"
	L"Copyright (C) 2015 THL A29 Limited, a Tencent company, and Milo Yip.  All rights reserved.\r\n"
	L"\r\n"
	L"If you have downloaded a copy of the RapidJSON binary from Tencent, please note that the RapidJSON binary is licensed under the MIT License.\r\n"
	L"If you have downloaded a copy of the RapidJSON source code from Tencent, please note that RapidJSON source code is licensed under the MIT License, except for the third-party components listed below which are subject to different license terms.  Your integration of RapidJSON into your own projects may require compliance with the MIT License, as well as the other licenses applicable to the third-party components included within RapidJSON. To avoid the problematic JSON license in your own projects, it's sufficient to exclude the bin/jsonchecker/ directory, as it's the only code under the JSON license.\r\n"
	L"A copy of the MIT License is included in this file.\r\n"
	L"\r\n"
	L"Other dependencies and licenses:\r\n"
	L"\r\n"
	L"Open Source Software Licensed Under the BSD License:\r\n"
	L"--------------------------------------------------------------------\r\n"
	L"\r\n"
	L"The msinttypes r29 \r\n"
	L"Copyright (c) 2006-2013 Alexander Chemeris \r\n"
	L"All rights reserved.\r\n"
	L"\r\n"
	L"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\r\n"
	L"\r\n"
	L"* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. \r\n"
	L"* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\r\n"
	L"* Neither the name of  copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\r\n"
	L"\r\n"
	L"THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\r\n"
	L"\r\n"
	L"Open Source Software Licensed Under the JSON License:\r\n"
	L"--------------------------------------------------------------------\r\n"
	L"\r\n"
	L"json.org \r\n"
	L"Copyright (c) 2002 JSON.org\r\n"
	L"All Rights Reserved.\r\n"
	L"\r\n"
	L"JSON_checker\r\n"
	L"Copyright (c) 2002 JSON.org\r\n"
	L"All Rights Reserved.\r\n"
	L"\r\n"
	L"\r\n"
	L"Terms of the JSON License:\r\n"
	L"---------------------------------------------------\r\n"
	L"\r\n"
	L"Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\r\n"
	L"\r\n"
	L"The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\r\n"
	L"\r\n"
	L"The Software shall be used for Good, not Evil.\r\n"
	L"\r\n"
	L"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\r\n"
	L"\r\n"
	L"\r\n"
	L"Terms of the MIT License:\r\n"
	L"--------------------------------------------------------------------\r\n"
	L"\r\n"
	L"Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\r\n"
	L"\r\n"
	L"The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\r\n"
	L"\r\n"
	L"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\r\n",
	
	// Dokany (mirror)

	L"project url: github.com/dokan-dev/dokany\r\n\r\n"
	L"cppcryptfs usage: code from the mirror.c sample program from Dokany was used in modifed form in cppcryptfs (in cryptdokan.cpp).\r\n\r\n"
	L"Dokany mirror.c copyright and license (MIT license):\r\n\r\n"
	L"Copyright (C) 2015 - 2018 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>\r\n"
	L"Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>\r\n"
	L"\r\n"
	L"Permission is hereby granted, free of charge, to any person obtaining a copy\r\n"
	L"of this software and associated documentation files (the \"Software\"), to deal\r\n"
	L"in the Software without restriction, including without limitation the rights\r\n"
	L"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\r\n"
	L"copies of the Software, and to permit persons to whom the Software is\r\n"
	L"furnished to do so, subject to the following conditions:\r\n"
	L"\r\n"
	L"The above copyright notice and this permission notice shall be included in\r\n"
	L"all copies or substantial portions of the Software.\r\n"
	L"\r\n"
	L"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\r\n"
	L"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\r\n"
	L"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\r\n"
	L"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\r\n"
	L"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\r\n"
	L"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\r\n"
	L"THE SOFTWARE.\r\n",

	// dokany (library)

	L"project url: github.com/dokan-dev/dokany\r\n\r\n"
	L"cppcryptfs usage: dynamically linked library\r\n\r\n"
	L"Dokany library copyright and license (GNU LGPL):\r\n\r\n"
	L"Copyright (C) 2015 - 2017 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>\r\n"
	L"Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>\r\n\r\n"
	L" GNU LESSER GENERAL PUBLIC LICENSE\r\n"
	L"                       Version 3, 29 June 2007\r\n"
	L"\r\n"
	L" Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>\r\n"
	L" Everyone is permitted to copy and distribute verbatim copies\r\n"
	L" of this license document, but changing it is not allowed.\r\n"
	L"\r\n"
	L"\r\n"
	L"  This version of the GNU Lesser General Public License incorporates\r\n"
	L"the terms and conditions of version 3 of the GNU General Public\r\n"
	L"License, supplemented by the additional permissions listed below.\r\n"
	L"\r\n"
	L"  0. Additional Definitions. \r\n"
	L"\r\n"
	L"  As used herein, \"this License\" refers to version 3 of the GNU Lesser\r\n"
	L"General Public License, and the \"GNU GPL\" refers to version 3 of the GNU\r\n"
	L"General Public License.\r\n"
	L"\r\n"
	L"  \"The Library\" refers to a covered work governed by this License,\r\n"
	L"other than an Application or a Combined Work as defined below.\r\n"
	L"\r\n"
	L"  An \"Application\" is any work that makes use of an interface provided\r\n"
	L"by the Library, but which is not otherwise based on the Library.\r\n"
	L"Defining a subclass of a class defined by the Library is deemed a mode\r\n"
	L"of using an interface provided by the Library.\r\n"
	L"\r\n"
	L"  A \"Combined Work\" is a work produced by combining or linking an\r\n"
	L"Application with the Library.  The particular version of the Library\r\n"
	L"with which the Combined Work was made is also called the \"Linked\r\n"
	L"Version\".\r\n"
	L"\r\n"
	L"  The \"Minimal Corresponding Source\" for a Combined Work means the\r\n"
	L"Corresponding Source for the Combined Work, excluding any source code\r\n"
	L"for portions of the Combined Work that, considered in isolation, are\r\n"
	L"based on the Application, and not on the Linked Version.\r\n"
	L"\r\n"
	L"  The \"Corresponding Application Code\" for a Combined Work means the\r\n"
	L"object code and/or source code for the Application, including any data\r\n"
	L"and utility programs needed for reproducing the Combined Work from the\r\n"
	L"Application, but excluding the System Libraries of the Combined Work.\r\n"
	L"\r\n"
	L"  1. Exception to Section 3 of the GNU GPL.\r\n"
	L"\r\n"
	L"  You may convey a covered work under sections 3 and 4 of this License\r\n"
	L"without being bound by section 3 of the GNU GPL.\r\n"
	L"\r\n"
	L"  2. Conveying Modified Versions.\r\n"
	L"\r\n"
	L"  If you modify a copy of the Library, and, in your modifications, a\r\n"
	L"facility refers to a function or data to be supplied by an Application\r\n"
	L"that uses the facility (other than as an argument passed when the\r\n"
	L"facility is invoked), then you may convey a copy of the modified\r\n"
	L"version:\r\n"
	L"\r\n"
	L"   a) under this License, provided that you make a good faith effort to\r\n"
	L"   ensure that, in the event an Application does not supply the\r\n"
	L"   function or data, the facility still operates, and performs\r\n"
	L"   whatever part of its purpose remains meaningful, or\r\n"
	L"\r\n"
	L"   b) under the GNU GPL, with none of the additional permissions of\r\n"
	L"   this License applicable to that copy.\r\n"
	L"\r\n"
	L"  3. Object Code Incorporating Material from Library Header Files.\r\n"
	L"\r\n"
	L"  The object code form of an Application may incorporate material from\r\n"
	L"a header file that is part of the Library.  You may convey such object\r\n"
	L"code under terms of your choice, provided that, if the incorporated\r\n"
	L"material is not limited to numerical parameters, data structure\r\n"
	L"layouts and accessors, or small macros, inline functions and templates\r\n"
	L"(ten or fewer lines in length), you do both of the following:\r\n"
	L"\r\n"
	L"   a) Give prominent notice with each copy of the object code that the\r\n"
	L"   Library is used in it and that the Library and its use are\r\n"
	L"   covered by this License.\r\n"
	L"\r\n"
	L"   b) Accompany the object code with a copy of the GNU GPL and this license\r\n"
	L"   document.\r\n"
	L"\r\n"
	L"  4. Combined Works.\r\n"
	L"\r\n"
	L"  You may convey a Combined Work under terms of your choice that,\r\n"
	L"taken together, effectively do not restrict modification of the\r\n"
	L"portions of the Library contained in the Combined Work and reverse\r\n"
	L"engineering for debugging such modifications, if you also do each of\r\n"
	L"the following:\r\n"
	L"\r\n"
	L"   a) Give prominent notice with each copy of the Combined Work that\r\n"
	L"   the Library is used in it and that the Library and its use are\r\n"
	L"   covered by this License.\r\n"
	L"\r\n"
	L"   b) Accompany the Combined Work with a copy of the GNU GPL and this license\r\n"
	L"   document.\r\n"
	L"\r\n"
	L"   c) For a Combined Work that displays copyright notices during\r\n"
	L"   execution, include the copyright notice for the Library among\r\n"
	L"   these notices, as well as a reference directing the user to the\r\n"
	L"   copies of the GNU GPL and this license document.\r\n"
	L"\r\n"
	L"   d) Do one of the following:\r\n"
	L"\r\n"
	L"       0) Convey the Minimal Corresponding Source under the terms of this\r\n"
	L"       License, and the Corresponding Application Code in a form\r\n"
	L"       suitable for, and under terms that permit, the user to\r\n"
	L"       recombine or relink the Application with a modified version of\r\n"
	L"       the Linked Version to produce a modified Combined Work, in the\r\n"
	L"       manner specified by section 6 of the GNU GPL for conveying\r\n"
	L"       Corresponding Source.\r\n"
	L"\r\n"
	L"       1) Use a suitable shared library mechanism for linking with the\r\n"
	L"       Library.  A suitable mechanism is one that (a) uses at run time\r\n"
	L"       a copy of the Library already present on the user's computer\r\n"
	L"       system, and (b) will operate properly with a modified version\r\n"
	L"       of the Library that is interface-compatible with the Linked\r\n"
	L"       Version. \r\n"
	L"\r\n"
	L"   e) Provide Installation Information, but only if you would otherwise\r\n"
	L"   be required to provide such information under section 6 of the\r\n"
	L"   GNU GPL, and only to the extent that such information is\r\n"
	L"   necessary to install and execute a modified version of the\r\n"
	L"   Combined Work produced by recombining or relinking the\r\n"
	L"   Application with a modified version of the Linked Version. (If\r\n"
	L"   you use option 4d0, the Installation Information must accompany\r\n"
	L"   the Minimal Corresponding Source and Corresponding Application\r\n"
	L"   Code. If you use option 4d1, you must provide the Installation\r\n"
	L"   Information in the manner specified by section 6 of the GNU GPL\r\n"
	L"   for conveying Corresponding Source.)\r\n"
	L"\r\n"
	L"  5. Combined Libraries.\r\n"
	L"\r\n"
	L"  You may place library facilities that are a work based on the\r\n"
	L"Library side by side in a single library together with other library\r\n"
	L"facilities that are not Applications and are not covered by this\r\n"
	L"License, and convey such a combined library under terms of your\r\n"
	L"choice, if you do both of the following:\r\n"
	L"\r\n"
	L"   a) Accompany the combined library with a copy of the same work based\r\n"
	L"   on the Library, uncombined with any other library facilities,\r\n"
	L"   conveyed under the terms of this License.\r\n"
	L"\r\n"
	L"   b) Give prominent notice with the combined library that part of it\r\n"
	L"   is a work based on the Library, and explaining where to find the\r\n"
	L"   accompanying uncombined form of the same work.\r\n"
	L"\r\n"
	L"  6. Revised Versions of the GNU Lesser General Public License.\r\n"
	L"\r\n"
	L"  The Free Software Foundation may publish revised and/or new versions\r\n"
	L"of the GNU Lesser General Public License from time to time. Such new\r\n"
	L"versions will be similar in spirit to the present version, but may\r\n"
	L"differ in detail to address new problems or concerns.\r\n"
	L"\r\n"
	L"  Each version is given a distinguishing version number. If the\r\n"
	L"Library as you received it specifies that a certain numbered version\r\n"
	L"of the GNU Lesser General Public License \"or any later version\"\r\n"
	L"applies to it, you have the option of following the terms and\r\n"
	L"conditions either of that published version or of any later version\r\n"
	L"published by the Free Software Foundation. If the Library as you\r\n"
	L"received it does not specify a version number of the GNU Lesser\r\n"
	L"General Public License, you may choose any version of the GNU Lesser\r\n"
	L"General Public License ever published by the Free Software Foundation.\r\n"
	L"\r\n"
	L"  If the Library as you received it specifies that a proxy can decide\r\n"
	L"whether future versions of the GNU Lesser General Public License shall\r\n"
	L"apply, that proxy's public statement of acceptance of any version is\r\n"
	L"permanent authorization for you to choose that version for the\r\n"
	L"Library.\r\n",
		
	// Secure Edit
	L"cppcryptfs usage: modified and incorporated into cppcryptfs (as SecureEdit.cpp and SecureEdit.h).\r\n\r\n"
	L"Secure Edit copyright and license:\r\n\r\n"
	L"100% free Secure Edit control MFC class\r\n"
	L"Copyright (c) 2003 Dominik Reichl\r\n"
	L"If you use this class I would be more than happy if you mention\r\n"
	L"my name somewhere in your application. Thanks!\r\n"
	L"Do you have any questions or want to tell me that you are using\r\n"
	L"my class, e-mail me: <dominik.reichl@t-online.de>.\r\n",

	// getopt

	L"project url: github.com/kimgr/getopt_port\r\n\r\n"
	L"cppcryptfs usage: getopt.c and getopt.h from this project were modified and incorporated into cppcryptfs.\r\n\r\n"
	L"getopt_port copyright and license:\r\n\r\n"
		L"Copyright (c) 2012-2017, Kim Grasman <kim.grasman@gmail.com>\r\n"
		L"All rights reserved.\r\n"
		L"\r\n"
		L"Redistribution and use in source and binary forms, with or without\r\n"
		L"modification, are permitted provided that the following conditions are met:\r\n"
		L"    * Redistributions of source code must retain the above copyright\r\n"
		L"      notice, this list of conditions and the following disclaimer.\r\n"
		L"    * Redistributions in binary form must reproduce the above copyright\r\n"
		L"      notice, this list of conditions and the following disclaimer in the\r\n"
		L"      documentation and/or other materials provided with the distribution.\r\n"
		L"    * Neither the name of Kim Grasman nor the\r\n"
		L"      names of contributors may be used to endorse or promote products\r\n"
		L"      derived from this software without specific prior written permission.\r\n"
		L"\r\n"
		L"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND\r\n"
		L"ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED\r\n"
		L"WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\r\n"
		L"DISCLAIMED. IN NO EVENT SHALL KIM GRASMAN BE LIABLE FOR ANY\r\n"
		L"DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\r\n"
		L"(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\r\n"
		L"LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND\r\n"
		L"ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\r\n"
		L"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS\r\n"
		L"SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\r\n",

	// aes-siv

	L"project url: github.com/arktronic/aes-siv\r\n\r\n"
	L"cppcryptfs usage: code from this project was modified and incorporated into cppcryptfs (in the cppcryptfs/aes-siv directory).  "
	L"The low-level, third-party AES implementation included with aes-siv was replaced with a new implementation that uses OpenSSL.\r\n\r\n"
	L"aes-siv copyright and license:\r\n\r\n"
	L"This project is licensed under the OSI-approved ISC License:\r\n"
	L"\r\n"
	L"Copyright (c) 2015 ARKconcepts / Sasha Kotlyar\r\n"
	L"\r\n"
	L"Permission to use, copy, modify, and/or distribute this software for any\r\n"
	L"purpose with or without fee is hereby granted, provided that the above\r\n"
	L"copyright notice and this permission notice appear in all copies.\r\n"
	L"\r\n"
	L"THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH\r\n"
	L"REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND\r\n"
	L"FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,\r\n"
	L"INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM\r\n"
	L"LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR\r\n"
	L"OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR\r\n"
	L"PERFORMANCE OF THIS SOFTWARE.\r\n",

	NULL
};

// CCryptAboutPropertyPage message handlers


BOOL CCryptAboutPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	wstring prod = L"cppryptfs";
	wstring ver = L"1.0";
	wstring copyright = L"Copyright (C) 2016-2019 Bailey Brown.  All Rights Reserved.";

	GetProductVersionInfo(prod, ver, copyright);

	string openssl_ver_s = SSLeay_version(SSLEAY_VERSION);

	// get rid of openssl build date

	int nspaces = 0;

	for (size_t i = 0; i < openssl_ver_s.length(); i++) {
		if (openssl_ver_s[i] == ' ') {
			if (nspaces) {
				openssl_ver_s.resize(i);
				break;
			}
			nspaces++;
		}
	}

	wstring openssl_ver_w;

	if (!utf8_to_unicode(openssl_ver_s.c_str(), openssl_ver_w))
		openssl_ver_w = L"error getting openssl version";

	CString openssl_ver = openssl_ver_w.c_str();

	std::vector<int> dv;
	std::wstring dok_ver;
	CString dokany_version;
	if (get_dokany_version(dok_ver, dv)) {
		dokany_version = CString(L"; using Dokany ") + dok_ver.c_str();
	}

	wstring bit_str = sizeof(void *) == 8 ? L" 64-bit" : L" 32-bit";

	wstring aes_ni;
	if (AES::use_aes_ni()) {
		aes_ni = bit_str + L"; AES-NI detected";
	} else {
		aes_ni = bit_str + L"; AES-NI not detected";
	}
 
	SetDlgItemText(IDC_LINKAGES, L"linked with " + openssl_ver + dokany_version);

	CString prod_ver = prod.c_str();
	prod_ver += L", Version ";
	prod_ver += &ver[0];

	SetDlgItemText(IDC_PROD_VERSION, prod_ver + CString(aes_ni.c_str()));
	SetDlgItemText(IDC_COPYRIGHT, copyright.c_str());

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_COMPONENTS_LIST);

	if (!pList)
		return FALSE;

	LRESULT Style = ::SendMessage(pList->m_hWnd, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);
	Style |= LVS_EX_FULLROWSELECT;
	::SendMessage(pList->m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, Style);
	
	pList->InsertColumn(0, L"Component", 0, 720);
	
	int i;

	for (i = 0; components[i]; i++)
		pList->InsertItem(i, components[i]);

	pList->SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
	


	CWnd *pWnd = GetDlgItem(IDC_INFO);

	if (pWnd) {
		pWnd->SetWindowTextW(licenses[0]);
		pWnd->PostMessageW(WM_CLEAR, 0, 0);
	}

//#define DUMP_LICENSE_INFO 1
#ifdef DUMP_LICENSE_INFO

	FILE *fl = NULL;

	if (fopen_s(&fl, "c:\\tmp\\foo4za8GeQG.txt", "wb") == 0) {

		for (i = 0; components[i]; i++) {
			std::string str;
			unicode_to_utf8(components[i], str);
			fwrite(str.c_str(), 1, str.length(), fl);
			unicode_to_utf8(licenses[i], str);
			fwrite(str.c_str(), 1, str.length(), fl);
		}

		fclose(fl);
	}
#endif

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CCryptAboutPropertyPage::OnEnChangeInfo()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CCryptPropertyPage::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}


void CCryptAboutPropertyPage::OnSetfocusInfo()
{
	// TODO: Add your control notification handler code here

	CEdit *pWnd = (CEdit*)GetDlgItem(IDC_INFO);

	if (!pWnd)
		return;

	pWnd->SetSel(-1, 0, TRUE);


}


void CCryptAboutPropertyPage::OnItemchangedComponentsList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;

	if (pNMLV->uNewState & LVIS_SELECTED) {

		CWnd *pWnd = GetDlgItem(IDC_INFO);

		if (pWnd) {
			if (pNMLV->iItem < sizeof(licenses) / sizeof(licenses[0])) {
				pWnd->SetWindowTextW(licenses[pNMLV->iItem]);
			} else {
				pWnd->SetWindowTextW(L"");
			}
			pWnd->PostMessageW(WM_CLEAR, 0, 0);
		}
	}
}
