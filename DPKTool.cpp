// DPKTool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DPKTool.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// The one and only application object

CWinApp theApp;

using namespace std;

//***********************************************************************
typedef struct _tagKeyInfo
{
	char BSN[32];
	char SSN[32];
	char PKID[32];
	char KEY[32];
	char WIFI[32];
	char BT[32];
	char IMEI[32];
	DWORD CRC;
}KeyInfo,*PKeyInfo;

KeyInfo m_KeyInfo;
DWORD CRC_Table[256];
char m_ip[32];
int m_port;
char m_szKey[32];
SOCKET gSocket=-1;
//***********************************************************************

void init_crc_table()  
{  
    DWORD c;  
    DWORD i, j;  
      
    for (i = 0; i < 256; i++) {  
        c = (DWORD)i;  
        for (j = 0; j < 8; j++) {  
            if (c & 1)  
                c = 0xedb88320L ^ (c >> 1);  
            else  
                c = c >> 1;  
        }  
        CRC_Table[i] = c;  
    }  
}  

DWORD CRC32(DWORD crc,BYTE *buffer, DWORD size)  
{  
    DWORD i;  
    for (i = 0; i < size; i++) {  
        crc = CRC_Table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);  
    }  
    return crc ;  
}  


#ifdef __IMEI_MAC

BOOL GetDeviceAddress()
{
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
	BOOL bWIFI = FALSE,bBT=FALSE,bRet = TRUE;

    unsigned int i;

    /* variables used for GetIfTable and GetIfEntry */
    MIB_IFTABLE *pIfTable;
    MIB_IFROW *pIfRow;

    // Allocate memory for our pointers.
    pIfTable = (MIB_IFTABLE *) MALLOC(sizeof (MIB_IFTABLE));
    if (pIfTable == NULL) {
		//MessageBox("Error allocating memory needed to call GetIfTable","Error",MB_ICONERROR);
        return FALSE;
    }
    // Make an initial call to GetIfTable to get the
    // necessary size into dwSize
    dwSize = sizeof (MIB_IFTABLE);
    if (GetIfTable(pIfTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pIfTable);
        pIfTable = (MIB_IFTABLE *) MALLOC(dwSize);
        if (pIfTable == NULL) {
			//MessageBox("Error allocating memory needed to call GetIfTable","Error",MB_ICONERROR); 
            return FALSE;
        }
    }

    // Make a second call to GetIfTable to get the actual
    // data we want.
    if ((dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE)) == NO_ERROR) 
	{
        for (i = 0; i < pIfTable->dwNumEntries; i++) {
            pIfRow = (MIB_IFROW *) & pIfTable->table[i];
            switch (pIfRow->dwType) {
            case IF_TYPE_ETHERNET_CSMACD:
				{
					if (strstr((char*)pIfRow->bDescr,"Bluetooth") && !bBT)
					{
						sprintf(m_KeyInfo.BT,"%02X-%02X-%02X-%02X-%02X-%02X",pIfRow->bPhysAddr[0],
							pIfRow->bPhysAddr[1],
							pIfRow->bPhysAddr[2],
							pIfRow->bPhysAddr[3],
							pIfRow->bPhysAddr[4],
							pIfRow->bPhysAddr[5]);
						bBT = TRUE;
					}
				}
                break;
            case IF_TYPE_IEEE80211:
				{
					if (strstr((char*)pIfRow->bDescr,"802.11") && !bWIFI)
					{
						sprintf(m_KeyInfo.WIFI,"%02X-%02X-%02X-%02X-%02X-%02X",pIfRow->bPhysAddr[0],
							pIfRow->bPhysAddr[1],
							pIfRow->bPhysAddr[2],
							pIfRow->bPhysAddr[3],
							pIfRow->bPhysAddr[4],
							pIfRow->bPhysAddr[5]);
						bWIFI = TRUE;
					}
				}
                break;
            default:
                //printf("Unknown type %ld\n", pIfRow->dwType);
                break;
            }
        }
    }

    if (pIfTable != NULL)
	{
        FREE(pIfTable);
        pIfTable = NULL;
    }

	return bRet;
}

BOOL GetIMEI()
{
    SAFEARRAY *psa = NULL;
	LONG lBound=0;
	BOOL bRet = FALSE;
	MBN_INTERFACE_CAPS InterfaceCaps;
	CComPtr<IMbnInterfaceManager>  pInterfaceMgr = NULL;
	CComPtr<IMbnInterface> pMbnInterface = NULL;
	HRESULT hr=CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) goto END;
    hr = CoCreateInstance(CLSID_MbnInterfaceManager,NULL,CLSCTX_ALL,IID_IMbnInterfaceManager,(void**)&pInterfaceMgr);
	if (FAILED(hr)) goto END;
	hr = pInterfaceMgr->GetInterfaces(&psa);
	if (FAILED(hr)) goto END;
	SafeArrayGetElement(psa, &lBound, &pMbnInterface);
	if (FAILED(hr)) goto END;
	hr = pMbnInterface->GetInterfaceCapability(&InterfaceCaps);
	if (FAILED(hr)) goto END;
	wchar_t* pBuf = InterfaceCaps.deviceID;
	wcstombs(m_KeyInfo.IMEI,pBuf,wcslen(pBuf));

    SysFreeString(InterfaceCaps.customDataClass);
    SysFreeString(InterfaceCaps.customBandClass);
    SysFreeString(InterfaceCaps.deviceID);
    SysFreeString(InterfaceCaps.manufacturer);
    SysFreeString(InterfaceCaps.model);
    SysFreeString(InterfaceCaps.firmwareInfo);

END:
	pInterfaceMgr = NULL;
	pMbnInterface = NULL;
	CoUninitialize();
	return bRet;
}

#endif

BOOL GetProductKey()
{
	BOOL retval,result=FALSE;
	PROCESS_INFORMATION pi={0};
	STARTUPINFOA si={0};
	SECURITY_ATTRIBUTES sa={0};
	HANDLE hReadPipe,hWritePipe;
	DWORD retcode = -1;
	CFile fp;

	memset(m_szKey,0,sizeof(m_szKey));
	sa.bInheritHandle=TRUE;
	sa.nLength=sizeof SECURITY_ATTRIBUTES;
	sa.lpSecurityDescriptor=NULL;
	retval=CreatePipe(&hReadPipe,&hWritePipe,&sa,0);
	if(retval)
	{
		si.cb=sizeof STARTUPINFO;
		si.wShowWindow=SW_HIDE;
		si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
		si.hStdOutput=si.hStdError=hWritePipe;
		retval=CreateProcessA(NULL,"cmd.exe /c Check.exe",&sa,&sa,TRUE,0,NULL,0,&si,&pi);
		if(retval)
		{
			DWORD dwLen,dwRead;
			WaitForSingleObject(pi.hThread,INFINITE);//等待命令行执行完毕
			GetExitCodeProcess(pi.hProcess,&retcode);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			if (retcode != 0)
			{
				goto end;
			}
			dwLen=GetFileSize(hReadPipe,NULL);
			char *buff=new char [dwLen+1];
			memset(m_szKey,0,sizeof(m_szKey));
			char* vptr,*token="Product key:       ";
			memset(buff,0,dwLen+1);
			retval=ReadFile(hReadPipe,buff,dwLen,&dwRead,NULL);
			vptr=strstr(buff+700,token);
			if (vptr)
			{
				vptr +=strlen(token);
				strncpy(m_szKey,vptr,29);
				result = TRUE;
			}
			delete buff;
		}
		if (result == FALSE)
		{
			goto end;
		}
		retval=CreateProcessA(NULL,"cmd.exe /c oa3tool.exe /report /configfile=oa3toolfile.cfg",&sa,&sa,TRUE,0,NULL,0,&si,&pi);
		if(retval)
		{
			DWORD dwLen;
			WaitForSingleObject(pi.hThread,INFINITE);//等待命令行执行完毕
			GetExitCodeProcess(pi.hProcess,&retcode);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			if (retcode)
			{
				goto end;
			}
			if (!fp.Open(TEXT("oa3.xml"),CFile::modeRead|CFile::typeBinary))
			{
				goto end;
			}
			dwLen=(DWORD)fp.GetLength();
			char* fBuff = new char[dwLen];
			char pkid[14]={0};
			fp.Read(fBuff,dwLen);
			fp.Close();
			char* dpk=strstr(fBuff,"<ProductKeyID>");
			if (dpk)
			{
				strncpy(m_KeyInfo.PKID,dpk+14,13);
			}
			delete fBuff;
		}
end:
		CloseHandle(hWritePipe);
		CloseHandle(hReadPipe);
	}
	return result;
}

BOOL ModifySerialNumber(char* strSN)
{
	CFile fp;
	if (!fp.Open(TEXT("oa3tool.cfg"),CFile::modeRead))
	{
		return FALSE;
	}
	char* szBuf,*pt,*pt2;
	DWORD dwLen = (DWORD)fp.GetLength();
	szBuf = new char[dwLen+1];
	memset(szBuf,0,dwLen+1);
	fp.Read(szBuf,dwLen);
	fp.Close();

	if (!fp.Open(TEXT("oa3tool.cfg"),CFile::modeReadWrite|CFile::modeCreate))
	{
		delete szBuf;
		return FALSE;
	}

	pt = strstr(szBuf,"<SerialNumber>");
	pt2 = strstr(szBuf,"</SerialNumber>");
	fp.Write(szBuf,pt-szBuf+strlen("<SerialNumber>"));
	fp.Write(strSN,strlen(strSN));
	fp.Write(pt2,strlen(pt2));
	fp.Close();
	delete szBuf;

	return TRUE;
}




UINT KeyThread()
{

	CFile fp;
	BOOL bHasSN = FALSE;
	memset(m_ip,0,sizeof(m_ip));
	m_port = 4000;

	CString szSN,szBSN;
	HANDLE hReadPipe,hWritePipe;
	char szTmp[1024]={0},szFileKeyID[32] = {0}, *szBuf=NULL, *pt=NULL;
	DWORD len,cnt,cnt2,retCode,dwLen,dwRead;
	BOOL bHasKey = FALSE,bHasCBR = FALSE,retval;
	int iCount,iVal;
	PROCESS_INFORMATION pi={0};
	STARTUPINFOA si={0};
	SECURITY_ATTRIBUTES sa={0};


	if (fp.Open(TEXT("oa3tool.cfg"),CFile::modeRead))
	{
		dwLen = (DWORD)fp.GetLength();
		szBuf = new char[dwLen];
		fp.Read(szBuf,dwLen);
		fp.Close();
		char *pt = strstr(szBuf,"<IPAddress>");
		char *pt2 = strstr(szBuf,"</IPAddress>");
		if (pt && pt2)
		{
			strncpy(m_ip,pt+11,pt2-pt-11);
		}
		pt = strstr(szBuf,"<SerialNumber>");
		pt2 = strstr(szBuf,"</SerialNumber>");
		if (pt && pt2)
		{
			bHasSN = TRUE;
		}
		delete szBuf;
	}

	if (inet_addr(m_ip) == INADDR_NONE)
	{
		printf(TEXT("Invalid ip address，please check ip address in oa3tool.cfg\n"));
		return -1;
	}
	if (!bHasSN)
	{
		printf(TEXT("Invalid SerialNumber，please check SN in oa3tool.cfg\n"));
		return -1;
	}





	sa.bInheritHandle=1;
	sa.nLength=sizeof SECURITY_ATTRIBUTES;
	sa.lpSecurityDescriptor=NULL;
	retval=CreatePipe(&hReadPipe,&hWritePipe,&sa,0);
	si.cb=sizeof STARTUPINFOA;
	si.wShowWindow=SW_HIDE;
	si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
	si.hStdOutput=si.hStdError=hWritePipe;

	printf(TEXT("connecting server......\n"));

	struct sockaddr_in  addr;//这是网络地址数据结构,服务端地址 
	addr.sin_family = AF_INET; 
	addr.sin_port = htons(4000); 
	addr.sin_addr.S_un.S_addr = inet_addr(m_ip);
	struct timeval timeout={10,0};//3s
	int ret=setsockopt(gSocket,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(timeout));
	ret=setsockopt(gSocket,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
	DWORD ul = 0;

	ioctlsocket(gSocket,FIONBIO,&ul);//blocking mode

	if(connect(gSocket,(sockaddr*)&addr,sizeof(addr)) != 0)
	{
		closesocket(gSocket);
		printf(TEXT("connect server failed\n"));
		goto __end;
	}

	Sleep(500);
	iVal=send(gSocket,"handshake",strlen("handshake"),0);
	Sleep(500);
	iVal=recv(gSocket,szTmp,1024,0);
	ul = GetLastError();
	if (iVal < 1 && strncmp(szTmp,"authorized",iVal))
	{
		printf(TEXT("authorized failed\n"));
		goto __end;
	}

	printf(TEXT("inquiring product key......\n"));
	bHasKey = GetProductKey();

	if (!bHasKey)
	{
		printf(TEXT("getting key from server......\n"));
		retval=CreateProcessA(NULL,"cmd.exe /c oa3tool.exe /assemble /configfile=oa3tool.cfg",&sa,&sa,0,0,NULL,NULL,&si,&pi);
		WaitForSingleObject(pi.hThread,INFINITE);
		GetExitCodeProcess(pi.hProcess,&retCode);
		if (retCode)
		{
			printf(TEXT("get key from server failed......\n"));
			goto __end;
		}
		//GetDeviceAddress();
		//GetIMEI();
		Sleep(500);
		if (fp.Open(TEXT("oa3.xml"),CFile::modeRead))
		{
			dwLen = (DWORD)fp.GetLength();
			szBuf = new char[dwLen];
			fp.Read(szBuf,dwLen);
			fp.Close();
			pt = strstr(szBuf,"<ProductKeyID>");
			if (pt)
			{
				strncpy(m_KeyInfo.PKID,pt+14,13);
				strncpy(szFileKeyID,pt+14,13);
			}
			pt = strstr(szBuf,"<ProductKey>");
			if (pt)
			{
				strncpy(m_KeyInfo.KEY,pt+12,29);
			}
			delete szBuf;
		}
		else
		{
			printf(TEXT("open oa3.xml failed\n"));
			goto __end;
		}

		printf(TEXT("Injecting key......\n"));
		retval=CreateProcessA(NULL,"cmd.exe /c afuwin.exe /oad",0,0,0,0,NULL,NULL,&si,&pi);
		WaitForSingleObject(pi.hThread,INFINITE);
		CreateProcessA(NULL,"cmd.exe /c afuwin.exe /aoa3.bin",0,0,0,0,NULL,NULL,&si,&pi);
		WaitForSingleObject(pi.hThread,INFINITE);
		GetExitCodeProcess(pi.hProcess,&retCode);

		if (retCode)
		{
			printf(TEXT("Inject key failed\n"));
			goto __end;
		}
		//----------------------------------------------------------------------
#if 1
		retval=CreateProcessA(NULL,"cmd.exe /c amidewin.exe /bs",&sa,&sa,TRUE,0,NULL,NULL,&si,&pi);
		if(retval)
		{
			WaitForSingleObject(pi.hThread,INFINITE);//等待命令行执行完毕
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			dwLen=GetFileSize(hReadPipe,NULL);
			char *buf=new char[dwLen+1];
			retval=ReadFile(hReadPipe,buf,dwLen,&dwRead,NULL);
			if (strlen(buf))
			{
				char* p1=strchr(buf,'"');
				if (p1)
				{
					p1++;
					char* p2=strchr(p1,'"');
					if (p2)
					{
						*p2 = 0;
						strcpy(m_KeyInfo.BSN,p1);
					}
				}
			}
			delete buf;
		}
		//----------------------------------------------------------------------
		retval=CreateProcessA(NULL,"cmd.exe /c amidewin.exe /ss",&sa,&sa,TRUE,0,NULL,NULL,&si,&pi);
		if(retval)
		{
			WaitForSingleObject(pi.hThread,INFINITE);//等待命令行执行完毕
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			dwLen=GetFileSize(hReadPipe,NULL);
			char *buf=new char[dwLen+1];
			retval=ReadFile(hReadPipe,buf,dwLen,&dwRead,NULL);
			if (strlen(buf))
			{
				char* p1=strchr(buf,'"');
				if (p1)
				{
					p1++;
					char* p2=strchr(p1,'"');
					if (p2)
					{
						*p2 = 0;
						strcpy(m_KeyInfo.SSN,p1);
					}
				}
			}
			delete buf;
		}
#endif
		//----------------------------------------------------------------------

		len=sizeof(KeyInfo) - 4;
		m_KeyInfo.CRC = CRC32(0xFFFFFFFF,(BYTE*)&m_KeyInfo,len);
		cnt = 1, cnt2 = 10;
		len = send(gSocket,(char*)&m_KeyInfo,sizeof(KeyInfo),0);
		Sleep(500);
		len = recv(gSocket,szTmp,1024,0);
		if (strncmp(szTmp,"techvision",len))
		{
			printf(TEXT("Upload CBR failed......\n"));
			goto __end;
		}

		printf(TEXT("comparing CBR, please wait......\n"));

		GetProductKey();

		if (strncmp(m_szKey,m_KeyInfo.KEY,strlen(m_KeyInfo.KEY)) == 0)//检查机器中的KEY是否和CBR中的一致
		{
			printf(TEXT("Uploading CBR......\n"));
			iCount = 5;
			while (iCount-- > 0)
			{
				retval=CreateProcessA(NULL,"cmd.exe /c oa3tool.exe /report /configfile=oa3tool.cfg",&sa,&sa,0,0,NULL,NULL,&si,&pi);
				WaitForSingleObject(pi.hThread,INFINITE);//等待命令行执行完毕
				GetExitCodeProcess(pi.hProcess,&retCode);
				if (retCode == 0)
				{
					bHasCBR = TRUE;
				}
				if (retCode == 0xc0000134)
				{
					break;
				}
			}
			if (retCode == 0xc0000134)
			{
				if (bHasCBR)
				{
					printf(TEXT("PKID:%s\n"),m_KeyInfo.PKID);
					printf(TEXT("Upload CBR successfully......\n"));
				}
				else
				{
					printf(TEXT("CBR has been uploaded......\n"));
				}
				goto __end;
			}
			else
			{
				printf(TEXT("Upload CBR failed......\n"));
				goto __end;
			}
		}
		else//刷完后两者不一致，需要重启才能生效
		{
			printf(TEXT("Cannot upload CBR until reboot device\n"));
			goto __end;
		}
	}
	else
	{
		printf(TEXT("Uploading CBR......\n"));
		iCount = 5;
		while (iCount-- > 0)
		{
			retval=CreateProcessA(NULL,"cmd.exe /c oa3tool.exe /report /configfile=oa3tool.cfg",&sa,&sa,0,0,NULL,NULL,&si,&pi);
			WaitForSingleObject(pi.hThread,INFINITE);//等待命令行执行完毕
			GetExitCodeProcess(pi.hProcess,&retCode);
			if (retCode == 0)
			{
				bHasCBR = TRUE;
			}
			if (retCode == 0xc0000134)
			{
				break;
			}
		}
		if (retCode == 0xc0000134)
		{
			if (bHasCBR)
			{
				printf(TEXT("PKID:%s\n"),m_KeyInfo.PKID);
				printf(TEXT("Upload CBR successfully......\n"));
			}
			else
			{
				printf(TEXT("PKID:%s\n"),m_KeyInfo.PKID);
				printf(TEXT("CBR has been uploaded......\n"));
			}
			goto __end;
		}
		else
		{
			printf(TEXT("Upload CBR failed......\n"));
			goto __end;
		}
	}

__end:
	CloseHandle(hWritePipe);
	CloseHandle(hReadPipe);

	return 0;
}
//********************************************************************************

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	// initialize MFC and print and error on failure
	if (!AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0))
	{
		// TODO: change error code to suit your needs
		_tprintf(_T("Fatal Error: MFC initialization failed\n"));
		nRetCode = 1;
	}
	else
	{
		// TODO: code your application's behavior here.
	}
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		return -1;
	}

	memset(&m_KeyInfo,0,sizeof(KeyInfo));
	init_crc_table();

	gSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (gSocket == 0)
	{
		printf(TEXT("network init failed\n"));
		return -1;
	}
//*********************************************************
	KeyThread();
	shutdown(gSocket,SD_BOTH);
	closesocket(gSocket);
//*********************************************************
	WSACleanup();
	return nRetCode;
}
