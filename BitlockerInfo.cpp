#include <windows.h>
#include <strsafe.h>
#include <iostream>

#define HAS_FLAG(var, flag)	(((var) & (flag)) == (flag))

struct FVE_STATUS
{
	uint32_t nSize;
	uint32_t nVersion;
	uint32_t nFlags;
	double ConversionPercent;
	uint64_t nConversionStatus;
};
using PFVE_STATUS = FVE_STATUS*;

struct FVE_AUTH_ELEMENT
{
	ULONG nSize;
	ULONG nVersion;
	ULONG nFlags;
	ULONG nType;
	BYTE nData[ANYSIZE_ARRAY];
};
using PFVE_AUTH_ELEMENT = FVE_AUTH_ELEMENT*;

struct FVE_AUTH_INFORMATION
{
	ULONG nSize;
	ULONG nVersion;
	ULONG nFlags;
	ULONG nElementsCount;
	PFVE_AUTH_ELEMENT *ppElements;
	PCWSTR szDescription;
	FILETIME ftCreationTime;
	GUID guid;
};
using PFVE_AUTH_INFORMATION = FVE_AUTH_INFORMATION*;

using PFNFVEGETSTATUS = HRESULT(WINAPI*)(HANDLE, PFVE_STATUS);
using PFNFVEGETSTATUSW = HRESULT(WINAPI*)(PCWSTR, PFVE_STATUS);

using PFNFVESETALLOWKEYEXPORT = HRESULT(WINAPI*)(BOOL);
using PFNFVEOPENVOLUMEW = HRESULT(WINAPI*)(PCWSTR, BOOL, PHANDLE);
using PFNFVECLOSEVOLUME = HRESULT(WINAPI*)(HANDLE);
using PFNFVEGETAUTHMETHODINFORMATION = HRESULT(WINAPI*)(HANDLE, PFVE_AUTH_INFORMATION, SIZE_T, PSIZE_T);
using PFNFVEGETAUTHMETHODGUIDS = HRESULT(WINAPI*)(HANDLE, GUID*, UINT, PUINT);

static constexpr auto RECOVERY_PASSWORD_KEY_PROTECTOR = 1;

// The following is my best guess at decoding the undocumented BitLocker flags after countless tests
#define FVE_ENCRYPTED		0x1
#define FVE_PENDING_REBOOT	0x2
#define UNKNOWN3			0x4
#define UNKNOWN4			0x8
#define FVE_DECRYPTING		0x10
#define FVE_ENCRYPTING		0x20
#define FVE_PAUSED			0x80

#define UNKNOWN8			0x100
#define UNKNOWN9			0x200
#define UNKNOWN10			0x400
#define FVE_ACTIVATED		0x1000
#define UNKNOWN12			0x2000
#define UNKNOWN13			0x4000

#define UNKNOWN14			0x20000
#define UNKNOWN15			0x40000
#define UNKNOWN16			0x200000
#define UNKNOWN17			0x400000

#define FVE_USED_SPACE_ONLY	0x1000000
#define UNKNOWN19			0x2000000

//#################################################################################################
int main(void)
{
	auto hFveApiDll = LoadLibraryEx(L"fveapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if(hFveApiDll)
	{
		PFNFVEGETSTATUS pfnFveGetStatus = (PFNFVEGETSTATUS)GetProcAddress(hFveApiDll, "FveGetStatus");
		PFNFVESETALLOWKEYEXPORT pfnFveSetAllowKeyExport = (PFNFVESETALLOWKEYEXPORT)GetProcAddress(hFveApiDll, "FveSetAllowKeyExport");
		PFNFVEOPENVOLUMEW pfnFveOpenVolumeW = (PFNFVEOPENVOLUMEW)GetProcAddress(hFveApiDll, "FveOpenVolumeW");
		PFNFVECLOSEVOLUME pfnFveCloseVolume = (PFNFVECLOSEVOLUME)GetProcAddress(hFveApiDll, "FveCloseVolume");
		PFNFVEGETAUTHMETHODINFORMATION pfnFveGetAuthMethodInformation = (PFNFVEGETAUTHMETHODINFORMATION)GetProcAddress(hFveApiDll, "FveGetAuthMethodInformation");;
		PFNFVEGETAUTHMETHODGUIDS pfnFveGetAuthMethodGuids = (PFNFVEGETAUTHMETHODGUIDS)GetProcAddress(hFveApiDll, "FveGetAuthMethodGuids");

		if(pfnFveSetAllowKeyExport && pfnFveOpenVolumeW && pfnFveCloseVolume && pfnFveGetAuthMethodInformation && pfnFveGetAuthMethodGuids)
		{	// You need to call FveSetAllowKeyExport(TRUE) in order extract the recovery key later on
			HRESULT hr = pfnFveSetAllowKeyExport(TRUE);
			if(SUCCEEDED(hr))
			{	// Open the drive using the device name syntax, e.g. \\.\C:
				wchar_t szDrive[7] = {L'\\', L'\\', L'.', L'\\', L'A', L':', L'\0'};
				DWORD dwDrives = GetLogicalDrives();
				std::wstring strStatus;

				for(wchar_t n = 0; n < 26 && dwDrives; ++n)
				{
					if(HAS_FLAG(dwDrives, 0x1))
					{
						szDrive[4] = L'A' + n;

						std::wcout << L"Drive " << (char)(L'A' + n) << L':' << std::endl;

						HANDLE hFveVolume = nullptr;
						hr = pfnFveOpenVolumeW(szDrive, FALSE, &hFveVolume);
						if(SUCCEEDED(hr))
						{
							FVE_STATUS fves = {0};
							fves.nSize = sizeof(fves);
							fves.nVersion = 1;

							if(pfnFveGetStatus && SUCCEEDED(pfnFveGetStatus(hFveVolume, &fves)))
							{
								bool bEncrypted = HAS_FLAG(fves.nFlags, FVE_ENCRYPTED);
								bool bReboot = HAS_FLAG(fves.nFlags, FVE_PENDING_REBOOT);
								bool bDecrypting = HAS_FLAG(fves.nFlags, FVE_DECRYPTING);
								bool bEncrypting = HAS_FLAG(fves.nFlags, FVE_ENCRYPTING);
								bool bPaused = HAS_FLAG(fves.nFlags, FVE_PAUSED);
								bool bActivated = HAS_FLAG(fves.nFlags, FVE_ACTIVATED);

								if(bEncrypted)
								{
									std::wstring strStatus;
									if(bActivated)
										strStatus = L"encrypted and activated";
									else if(bDecrypting)
										strStatus = L"decrypting";
									else if(bEncrypting)
										strStatus =  L"encrypting";
									else
										strStatus = L"encrypted with clear-text password";

									std::wcout << L"  Status: " << strStatus << std::endl;
								}

								if(bPaused)
									std::wcout << L"  Paused" << std::endl;

								if(bReboot)
									std::wcout << L"  Reboot required" << std::endl;
							}

							UINT nGuidCount = 0;
							hr = pfnFveGetAuthMethodGuids(hFveVolume, nullptr, 0, &nGuidCount);
							if(SUCCEEDED(hr) && nGuidCount)
							{
								auto pGuids = std::make_unique<GUID[]>(nGuidCount);
								hr = pfnFveGetAuthMethodGuids(hFveVolume, pGuids.get(), nGuidCount, &nGuidCount);
								if(SUCCEEDED(hr))
								{
									SIZE_T nRequiredSize = 0;
									FVE_AUTH_INFORMATION FveAuthInfo = {0};
									FveAuthInfo.nSize = sizeof(FveAuthInfo);

									for(UINT nGuid = 0; nGuid < nGuidCount; ++nGuid)
									{
										FveAuthInfo.nVersion = 1;
										FveAuthInfo.nFlags = 1;
										FveAuthInfo.guid = pGuids.get()[nGuid];

										PFVE_AUTH_INFORMATION pFveAuthInfo = &FveAuthInfo;

										hr = pfnFveGetAuthMethodInformation(hFveVolume, pFveAuthInfo, sizeof(FveAuthInfo), &nRequiredSize);
										if(FAILED(hr) && HRESULT_CODE(hr) == ERROR_INSUFFICIENT_BUFFER)
										{
											auto pBuf = std::make_unique<BYTE[]>(nRequiredSize);
											pFveAuthInfo = (PFVE_AUTH_INFORMATION)pBuf.get();
											pFveAuthInfo->nSize = FveAuthInfo.nSize;
											pFveAuthInfo->nVersion = FveAuthInfo.nVersion;
											pFveAuthInfo->nFlags = FveAuthInfo.nFlags;
											pFveAuthInfo->guid = FveAuthInfo.guid;

											hr = pfnFveGetAuthMethodInformation(hFveVolume, pFveAuthInfo, nRequiredSize, &nRequiredSize);
											if(SUCCEEDED(hr) && pFveAuthInfo->ppElements[0]->nType == RECOVERY_PASSWORD_KEY_PROTECTOR)
											{
												FveAuthInfo.nVersion = 1;
												FveAuthInfo.nFlags = 0x00080002;
												FveAuthInfo.guid = pGuids.get()[nGuid];

												pFveAuthInfo = &FveAuthInfo;

												hr = pfnFveGetAuthMethodInformation(hFveVolume, pFveAuthInfo, sizeof(FveAuthInfo), &nRequiredSize);
												if(FAILED(hr) && HRESULT_CODE(hr) == ERROR_INSUFFICIENT_BUFFER)
												{
													pBuf = std::make_unique<BYTE[]>(nRequiredSize);
													pFveAuthInfo = (PFVE_AUTH_INFORMATION)pBuf.get();
													pFveAuthInfo->nSize = FveAuthInfo.nSize;
													pFveAuthInfo->nVersion = FveAuthInfo.nVersion;
													pFveAuthInfo->nFlags = FveAuthInfo.nFlags;
													pFveAuthInfo->guid = FveAuthInfo.guid;

													hr = pfnFveGetAuthMethodInformation(hFveVolume, pFveAuthInfo, nRequiredSize, &nRequiredSize);
													if(SUCCEEDED(hr))
													{
														PWSTR szUuid = nullptr;
														if(SUCCEEDED(StringFromIID(pFveAuthInfo->guid, &szUuid)))
														{
															std::wcout << L"  Drive ID: " << szUuid << std::endl;
															CoTaskMemFree(szUuid);
														}

														std::wstring strKey;
														wchar_t szBlock[8] = {0};
														for(int n = 0; n < 8; ++n)
														{
															UINT uBlock = pFveAuthInfo->ppElements[0]->nData[n * 2 + 1];
															uBlock *= 256;
															uBlock += pFveAuthInfo->ppElements[0]->nData[n * 2];
															uBlock *= 11;

															if(FAILED(StringCchPrintfW(szBlock, 8, L"%06d", uBlock)))
																break;

															strKey += szBlock;
															if(n < 7)
																strKey += L'-';
														}

														std::wcout << L"  Recovery key: " << strKey << std::endl;
													}
												}
											}
										}
									}
								}
							}

							pfnFveCloseVolume(hFveVolume);
						}
					}

					dwDrives >>= 1;
				}
			}
		}
	}

	return NO_ERROR;
}
