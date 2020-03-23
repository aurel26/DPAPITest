#include <windows.h>
#include <stdio.h>

#define TEST_BLOC_SIZE        4

BOOL
WriteFileToDisk (
   _In_z_ LPWSTR szFileName,
   _In_ PBYTE pbData,
   _In_ ULONG cbData
)
{
   BOOL bResult;
   HANDLE hFile;
   DWORD dwDataWritten;

   hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      fwprintf(stderr, L"CreateFile(%s) failed (error %u).\n", szFileName, GetLastError());
      return FALSE;
   }

   bResult = WriteFile(hFile, pbData, cbData, &dwDataWritten, NULL);
   if (bResult == FALSE)
   {
      fwprintf(stderr, L"WriteFile() failed (error %u).\n", GetLastError());
      CloseHandle(hFile);
      return FALSE;
   }

   wprintf(L"Protected test blob successfully written.\n");
   CloseHandle(hFile);
   return TRUE;
}

void
PrintUsage(
   _In_z_ LPWSTR szAppName
)
{
   fwprintf(stderr, L"%s: [Protect|Unprotect] datafile.bin\n", szAppName);
}

int
wmain(
   int argc,
   wchar_t *argv[]
)
{
   BOOL bResult;

   HANDLE hHeap;
   HANDLE hFile;

   LPWSTR szDesc;
   DATA_BLOB DataIn = { 0 };
   DATA_BLOB DataOut = { 0 };

   if (argc != 3)
   {
      PrintUsage(L"TestDPAPI");
      return EXIT_FAILURE;
   }

   hHeap = HeapCreate(0, 0, 0);
   if (hHeap == NULL)
      return EXIT_FAILURE;

   if (_wcsicmp(argv[1], L"Unprotect") == 0)
   {
      PBYTE pbDataIn;

      DWORD dwFileSize;
      DWORD dwDataReaden;

      hFile = CreateFile(argv[2], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
      if (hFile == INVALID_HANDLE_VALUE)
      {
         fwprintf(stderr, L"CreateFile(%s) failed (error %u).\n", argv[2], GetLastError());
         return EXIT_FAILURE;
      }
      dwFileSize = GetFileSize(hFile, NULL);

      pbDataIn = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize);
      if (pbDataIn != NULL)
      {
         bResult = ReadFile(hFile, pbDataIn, dwFileSize, &dwDataReaden, NULL);
         if (bResult == FALSE)
         {
            fwprintf(stderr, L"ReadFile failed (error %u).\n", GetLastError());
            return EXIT_FAILURE;
         }

         DataIn.cbData = dwDataReaden;
         DataIn.pbData = pbDataIn;
         bResult = CryptUnprotectData(&DataIn, &szDesc, NULL, NULL, NULL, 0, &DataOut);
         if (bResult == FALSE)
         {
            fwprintf(stderr, L"CryptUnprotectData failed (error %u).\n", GetLastError());
            CloseHandle(hFile);
            return EXIT_FAILURE;
         }
         else
         {
            PBYTE pbDataOut;

            pbDataOut = DataOut.pbData;

            if (DataOut.cbData != TEST_BLOC_SIZE)
            {
               fwprintf(stderr, L"Wrong size (%u != %u).\n", DataOut.cbData, TEST_BLOC_SIZE);
            }
            else if ((pbDataOut[0] != 0x12) || (pbDataOut[1] != 0x34) || (pbDataOut[2] != 0x56) || (pbDataOut[3] != 0x78))
            {
               fwprintf(stderr, L"Unprotected data is incorrect.\n");
            }
            else
            {
               wprintf(L"Unprotected data is correct.\n");
            }

            LocalFree(pbDataOut);
            CloseHandle(hFile);
         }

         HeapFree(hHeap, 0, pbDataIn);
      }
   }
   else if (_wcsicmp(argv[1], L"Protect") == 0)
   {
      BYTE pbData[TEST_BLOC_SIZE];

      pbData[0] = 0x12;
      pbData[1] = 0x34;
      pbData[2] = 0x56;
      pbData[3] = 0x78;
      DataIn.cbData = TEST_BLOC_SIZE;
      DataIn.pbData = pbData;

      bResult = CryptProtectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut);
      if (bResult == FALSE)
      {
         fwprintf(stderr, L"CryptProtectData failed (error %u).\n", GetLastError());
         return EXIT_FAILURE;
      }
      else
      {
         WriteFileToDisk(argv[2], DataOut.pbData, DataOut.cbData);
      }
   }
   else
   {
      PrintUsage(argv[0]);
      return EXIT_FAILURE;
   }

   HeapDestroy(hHeap);

   return EXIT_SUCCESS;
}
