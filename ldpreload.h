#ifndef LDPRELOAD_H
#define LDPRELOAD_H

void pwerror(const char* szPrefix, DWORD dwErr);

#define Chk(f) \
	do \
		{ \
		hr = (f); \
		if (FAILED(hr)) \
			goto Error; \
		} \
	while (FALSE)

#define ChkTrue(f, err) \
	do \
		{ \
		if (!(f)) \
			{ \
			hr = err; \
			goto Error; \
			} \
		} \
	while (FALSE)

#define ChkTrueGetLastError(f) \
	do \
		{ \
		if (!(f)) \
			{ \
			DWORD	dwErr = GetLastError(); \
			hr = HRESULT_FROM_WIN32(dwErr); \
			goto Error; \
			} \
		} \
	while (FALSE)

#define ChkTruePrintLastError(f, str) \
	do \
		{ \
		if (!(f)) \
			{ \
			DWORD dwErr = GetLastError(); \
			pwerror(str, dwErr); \
			hr = HRESULT_FROM_WIN32(dwErr); \
			goto Error; \
			} \
		} \
	while (FALSE)

		
#endif