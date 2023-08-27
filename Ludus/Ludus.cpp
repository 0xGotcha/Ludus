#include "globals.h"
#include <cxxopts.hpp>
#include <iomanip>


// Dynamically resolved functions
typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);


typedef struct timeKeeper {
    uint64_t timeUpperA;
    uint64_t timeLowerA;
    uint64_t timeUpperB;
    uint64_t timeLowerB;
} TimeKeeper;

#ifdef _WIN64
extern "C"
{
    int adbg_BeingDebuggedPEBx64(void);
    int adbg_NtGlobalFlagPEBx64(void);
    void adbg_GetTickCountx64(void);
    void adbg_QueryPerformanceCounterx64(void);
    void adbg_RDTSCx64(TimeKeeper*);
    void adbg_Int2Dx64(void);
    void adbg_Int3x64(void);
    void adbg_SingleStepExceptionx64(void);
};
#endif

void adbg_CheckRemoteDebuggerPresent()
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &found);
    PrintInstructionsAroundAddress(&CheckRemoteDebuggerPresent);

    if (found)
    {
        log("Caught by CheckRemoteDebuggerPresent!", 0);
        log("https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent", 2);
        log("If the function succeeds, the return value is nonzero.", 2);
        log("Check the instructions \n       cmp dword ptr [rsp+0x40], 0x00\n       jz 0x00007FF?????????", 2);
        getchar();
        exit(0);
    }
}

void adbg_IsDebuggerPresent()
{
   
    BOOL found = FALSE;

    found = IsDebuggerPresent();

    PrintInstructionsAroundAddress(&IsDebuggerPresent);

    if (found)
    {
        log("Caught by IsDebuggerPresent!", 0);
        log("https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent", 2);
        log("If the current process is running in the context of a debugger, the return value is nonzero.",2);
        log("If the current process is not running in the context of a debugger, the return value is zero.", 2);
        getchar();
        exit(0);
    }
}

void adbg_RDTSC()
{
    BOOL found = FALSE;

#ifdef _WIN64
    uint64_t timeA = 0;
    uint64_t timeB = 0;
    TimeKeeper timeKeeper = { 0 };
    adbg_RDTSCx64(&timeKeeper);

    timeA = timeKeeper.timeUpperA;
    timeA = (timeA << 32) | timeKeeper.timeLowerA;

    timeB = timeKeeper.timeUpperB;
    timeB = (timeB << 32) | timeKeeper.timeLowerB;

    // 0x100000 is purely empirical and is based on the CPU clock speed
    // This value should be change depending on the length and complexity of 
    // code between each RDTSC operation.

    if (timeB - timeA > 0x100000)
    {
        found = TRUE;
    }

#else
    int timeUpperA = 0;
    int timeLowerA = 0;
    int timeUpperB = 0;
    int timeLowerB = 0;
    int timeA = 0;
    int timeB = 0;

    _asm
    {
        // rdtsc stores result across EDX:EAX
        rdtsc;
        mov[timeUpperA], edx;
        mov[timeLowerA], eax;

        // Junk code to entice stepping through or a breakpoint
        xor eax, eax;
        mov eax, 5;
        shr eax, 2;
        sub eax, ebx;
        cmp eax, ecx;

        rdtsc;
        mov[timeUpperB], edx;
        mov[timeLowerB], eax;
    }

    timeA = timeUpperA;
    timeA = (timeA << 32) | timeLowerA;

    timeB = timeUpperB;
    timeB = (timeB << 32) | timeLowerB;

    // 0x100000 is purely empirical and is based on the CPU clock speed
    // This value should be change depending on the length and complexity of 
    // code between each RDTSC operation.

    if (timeB - timeA > 0x10000)
    {
        found = TRUE;
    }

#endif

    if (found)
    {
        log("Caught by DBG_RDTSC", 0);
        log("NOP the call to the function to RDTSC", 2);
        exit(0);
    }
}



void adbg_NtGlobalFlagPEB()
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_NtGlobalFlagPEBx64();

    
    PrintInstructionsAroundAddress(reinterpret_cast<void*>(adbg_NtGlobalFlagPEBx64));
  
#else
    _asm
    {
        xor eax, eax;			// clear eax
        mov eax, fs: [0x30] ;	// Reference start of the PEB
        mov eax, [eax + 0x68];	// PEB+0x68 points to NtGlobalFlag
        and eax, 0x00000070;	// check three flags:
        //   FLG_HEAP_ENABLE_TAIL_CHECK   (0x10)
        //   FLG_HEAP_ENABLE_FREE_CHECK   (0x20)
        //   FLG_HEAP_VALIDATE_PARAMETERS (0x40)
        mov found, eax;			// Copy result into 'found'
    }
#endif

    if (found)
    {
        log( "Caught by NtGlobalFlag PEB check!", 1);
        exit(0);
    }
}

void adbg_NtQueryInformationProcess()
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION pProcBasicInfo = { 0 };
    ULONG returnLength = 0;

    // Get a handle to ntdll.dll so we can import NtQueryInformationProcess
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    // Dynamically acquire the addres of NtQueryInformationProcess
    _NtQueryInformationProcess  NtQueryInformationProcess = NULL;
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess == NULL)
    {
        return;
    }

    hProcess = GetCurrentProcess();

    // Note: There are many options for the 2nd parameter NtQueryInformationProcess
    // (ProcessInformationClass) many of them are opaque. While we use ProcessBasicInformation (0), 
    // we could also use:
    //      ProcessDebugPort (7)
    //      ProcessDebugObjectHandle (30)
    //      ProcessDebugFlags (31)
    // There are likely others. You can find many other options for ProcessInformationClass over at PINVOKE:
    //      https://www.pinvoke.net/default.aspx/ntdll/PROCESSINFOCLASS.html
    // Keep in mind that NtQueryInformationProcess will return different things depending on the ProcessInformationClass used.
    // Many online articles using NtQueryInformationProcess for anti-debugging will use DWORD types for NtQueryInformationProcess 
    // paramters. This is fine for 32-builds with some ProcessInformationClass values, but it will cause some to fail on 64-bit builds.
    // In the event of a failure NtQueryInformationProcess will likely return STATUS_INFO_LENGTH_MISMATCH (0xC0000004). 

    // Query ProcessDebugPort
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pProcBasicInfo, sizeof(pProcBasicInfo), &returnLength);
    if (NT_SUCCESS(status)) {
        PPEB pPeb = pProcBasicInfo.PebBaseAddress;
        if (pPeb)
        {
            if (pPeb->BeingDebugged)
            {
               log("Caught by NtQueryInformationProcess (ProcessDebugPort)!",0);
               log("Find test rax,rax and the next instruction is JNE which you can change to JMP to bypass check", 2);
               log("https://www.pinvoke.net/default.aspx/ntdll/PROCESSINFOCLASS.html", 2);
               log("Keep in mind that NtQueryInformationProcess will return different things depending on the ProcessInformationClass used.", 2);
               log("In the event of a failure NtQueryInformationProcess will likely return STATUS_INFO_LENGTH_MISMATCH (0xC0000004).", 2);
               getchar();
                exit(0);
            }
        }
    }
}


void adbg_ProcessFileName(void)
{
    // detect debugger by process file (for example: ollydbg.exe)
    const wchar_t* debuggersFilename[6] = {
        L"cheatengine-x86_64.exe",
        L"ollydbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"radare2.exe",
        L"x64dbg.exe"
    };

    wchar_t* processName;
    PROCESSENTRY32W processInformation{ sizeof(PROCESSENTRY32W) };
    HANDLE processList;

    processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    processInformation = { sizeof(PROCESSENTRY32W) };
    if (!(Process32FirstW(processList, &processInformation)))
        printf("[Warning] It is impossible to check process list.");
    else
    {
        do
        {
            for (const wchar_t* debugger : debuggersFilename)
            {
                processName = processInformation.szExeFile;
                if (_wcsicmp(debugger, processName) == 0) {
                    log("Detected a analyst tool running..", 2);
                    getchar();
                    exit(0);
                }
            }
        } while (Process32NextW(processList, &processInformation));
    }
    CloseHandle(processList);
}

void adbg_CheckWindowClassName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowClassNameOlly = L"OLLYDBG";		// OllyDbg
    const wchar_t* WindowClassNameImmunity = L"ID";			// Immunity Debugger

    // Check for OllyDBG class name
    hWindow = FindWindow(WindowClassNameOlly, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    // Check for Immunity class name
    hWindow = FindWindow(WindowClassNameImmunity, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        log("Found OLLYDBG or Immunity debugger running.", 2);
        getchar();
        exit(0);
    }
}


void adbg_NtSetInformationThread(void)
{
    THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

    // Get a handle to ntdll.dll so we can import NtSetInformationThread
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    // Dynamically acquire the addres of NtSetInformationThread and NtQueryInformationThread
    _NtSetInformationThread NtSetInformationThread = NULL;
    NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (NtSetInformationThread == NULL)
    {
        return;
    }

    // There is nothing to check here after this call.
    NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}


void adbg_DebugActiveProcess(const char* cpid)
{
    BOOL found = FALSE;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    TCHAR szPath[MAX_PATH];
    DWORD exitCode = 0;

    CreateMutex(NULL, FALSE, L"Ludus");
    if (GetLastError() != ERROR_SUCCESS)
    {
        // If we get here we are in the child process
        if (DebugActiveProcess((DWORD)atoi(cpid)))
        {
            // No debugger found.
            return;
        }
        else
        {

            // Debugger found, exit child with a unique code we can check for.
            exit(555);
        }
    }
    // parent process
    DWORD pid = GetCurrentProcessId();
    GetModuleFileName(NULL, szPath, MAX_PATH);

    char cmdline[MAX_PATH + 1 + sizeof(int)];
    snprintf(cmdline, sizeof(cmdline), "%ws %d", szPath, pid);

    // Start the child process. 
    BOOL success = CreateProcessA(
        NULL,		// path (NULL means use cmdline instead)
        cmdline,	// Command line
        NULL,		// Process handle not inheritable
        NULL,		// Thread handle not inheritable
        FALSE,		// Set handle inheritance to FALSE
        0,			// No creation flags
        NULL,		// Use parent's environment block
        NULL,		// Use parent's starting directory 
        &si,		// Pointer to STARTUPINFO structure
        &pi);		// Pointer to PROCESS_INFORMATION structure

    // Wait until child process exits and get the code
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Check for our unique exit code
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCode == 555)
    {
        found = TRUE;
    }

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (found)
    {
        log("Debugger found, exit child with a unique code we can check for.", 2);
        getchar();
        exit(0);
    }

}

void adbg_QueryPerformanceCounter(void)
{
    BOOL found = FALSE;
    LARGE_INTEGER t1;
    LARGE_INTEGER t2;

    QueryPerformanceCounter(&t1);

#ifdef _WIN64
    adbg_QueryPerformanceCounterx64();
#else
    // Junk or legit code.
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    QueryPerformanceCounter(&t2);

    // 30 is an empirical value
    if ((t2.QuadPart - t1.QuadPart) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
      
        log("Caught by QueryPerformanceCounter!", 0);
        getchar();
        exit(0);
    }
}


void adbg_GetTickCount(void)
{
    BOOL found = FALSE;
    DWORD t1;
    DWORD t2;

    t1 = GetTickCount();

#ifdef _WIN64
    adbg_GetTickCountx64();
#else
    // Junk or legit code.
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    t2 = GetTickCount();

    // 30 milliseconds is an empirical value
    if ((t2 - t1) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
     
        log("Caught by GetTickCount!", 0);
        getchar();
        exit(0);
    }
}

// =======================================================================
// CPU Checks
// These checks focus on aspects of the CPU, including hardware break-
// points, special interrupt opcodes, and flags.
// =======================================================================

void adbg_HardwareDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
        {
            found = TRUE;
        }
    }

    if (found)
    {
        log("Caught by a Hardware Debug Register Check!", 0);
        getchar();
        exit(0);
    
    }
}


void adbg_MovSS(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    // This method does not work on x64
#else
    _asm
    {
        push ss;
        pop ss;
        pushfd;
        test byte ptr[esp + 1], 1;
        jne fnd;
        jmp end;
    fnd:
        mov found, 1;
    end:
        nop;
    }
#endif

    if (found)
    {
        log("Caught by a MOV SS Single Step Check!", 0);
        getchar();
        exit(0);
     
    }
}

void adbg_CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xBEEF; // an invalid handle

    try
    {
        CloseHandle(hInvalid);
    }
    catch (const std::exception& ex)
    {
        log("Caught an exception: " + std::string(ex.what()), 0);
        getchar();
        exit(0);
    }
}


void adbg_SingleStepException(void)
{
    DWORD found = TRUE;

    // In this method we force an exception to occur. If it occurs
    // outside of a debugger, the __except() handler is called setting
    // found to FALSE. If the exception occurs inside of a debugger, the
    // __except() will not be called (in certain cases) leading to
    // found being TRUE.

    try
    {
#ifdef _WIN64
        adbg_SingleStepExceptionx64();
#else
        _asm
        {
            pushfd;						// save EFFLAGS register
            or byte ptr[esp + 1], 1;	// set trap flag in EFFLAGS
            popfd;						// restore EFFLAGS register
        }
#endif
    }
    catch (const std::exception& ex)
    {
        found = FALSE;
    }

    if (found)
    {
       
        log("Caught by a Single Step Exception!", 0);
        getchar();
        exit(0);
        
    }
}


void adbg_Int3(void)
{
    BOOL found = TRUE;

    try
    {
#ifdef _WIN64
        adbg_Int3x64();
#else
        _asm
        {
            int 3;	// 0xCC standard software breakpoint
        }
#endif
    }

    catch (const std::exception& ex)
    {
        found = FALSE;
    }

    if (found)
    {
        log("Caught by a rogue INT 3!", 0);
        getchar();
        exit(0);
      
    }
}


void adbg_PrefixHop(void)
{
    BOOL found = TRUE;

    try
    {
#ifdef _WIN64
        // TODO: Not yet implemented in x64
        found = FALSE;
#else
        _asm
        {
            __emit 0xF3;	// 0xF3 0x64 is the prefix 'REP'
            __emit 0x64;
            __emit 0xCC;	// this gets skipped over if being debugged
        }
#endif
    }

    catch (const std::exception& ex)
    {
        found = FALSE;
    }

    if (found)
    {
        log("Caught by a Prefix Hop!", 0);
        getchar();
        exit(0);
    
    }
}


void adbg_Int2D(void)
{
    BOOL found = TRUE;

    try
    {
#ifdef _WIN64
        adbg_Int2Dx64();
#else
        _asm
        {
            int 0x2D;
            nop;
        }
#endif
    }

    catch (const std::exception& ex)
    {
        found = FALSE;
    }

    if (found)
    {
       
        log("Caught by a rogue INT 2D!", 0);
        getchar();
        exit(0);
    }
}





//
//int main(int argc, char* argv[]) {
//cxxopts::Options options("Ludus", "In Ancient Rome, a \"ludus\" referred to a training school for gladiators. Gladiators were combatants who fought in arenas as a form of entertainment. These schools, or ludus, were where gladiators were trained, equipped, and prepared for their battles in the arenas.");
//
//    options.add_options()
//        ("h,help", "Show help")
//        ("f,function", "Function to call (ProcessFileName, CheckWindowClassName, NtSetInformationThread, DebugActiveProcess, QueryPerformanceCounter, GetTickCount, HardwareDebugRegisters, MovSS, CloseHandleException, SingleStepException, Int3, PrefixHop, Int2D)", cxxopts::value<std::string>())
//        ;
//
//    options.parse_positional({ "function" });
//
//    auto result = options.parse(argc, argv);
//
//    if (result.count("help") || argc == 1) {  // Display custom help message if explicitly requested or if no arguments provided
//        std::cout << "Usage: " << argv[0] << " [options] [function]" << std::endl;
//        std::cout << "Options:" << std::endl;
//        std::cout << "  -h, --help                 Show help" << std::endl;
//        std::cout << "  -f, --function=<function>  Function to call (ProcessFileName, CheckWindowClassName, NtSetInformationThread, DebugActiveProcess, QueryPerformanceCounter, GetTickCount, HardwareDebugRegisters, MovSS, CloseHandleException, SingleStepException, Int3, PrefixHop, Int2D)" << std::endl;
//        std::cout << std::endl;
//        std::cout << "In Ancient Rome, a \"ludus\" referred to a training school for gladiators. Gladiators were combatants who fought in arenas as a form of entertainment. These schools, or ludus, were where gladiators were trained, equipped, and prepared for their battles in the arenas." << std::endl;
//        return 0;
//    }
//
//    if (result.count("function")) {
//        std::string function = result["function"].as<std::string>();
//
//        if (function == "RDTSC") {
//            log("Calling adbg_RDTSC()\n", 2);
//            // Call adbg_RDTSC() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_RDTSC);
//            adbg_RDTSC();
//        }
//        else if (function == "IsDebuggerPresent") {
//            log("Calling adbg_IsDebuggerPresent()\n", 2);
//            // Call adbg_IsDebuggerPresent() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_IsDebuggerPresent);
//            adbg_IsDebuggerPresent();
//        }
//        else if (function == "NtQueryInformationProcess") {
//            log("Calling adbg_NtQueryInformationProcess()\n", 2);
//            // Call adbg_NtQueryInformationProcess() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_NtQueryInformationProcess);
//            adbg_NtQueryInformationProcess();
//        }
//        else if (function == "CheckRemoteDebuggerPresent") {
//            log("Calling adbg_CheckRemoteDebuggerPresent()\n", 2);
//            // Call adbg_CheckRemoteDebuggerPresent() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_CheckRemoteDebuggerPresent);
//            adbg_CheckRemoteDebuggerPresent();
//        }
//        if (function == "ProcessFileName") {
//            log("Calling adbg_ProcessFileName()\n", 2);
//            // Call adbg_ProcessFileName() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_ProcessFileName);
//            adbg_ProcessFileName();
//        }
//        else if (function == "CheckWindowClassName") {
//            log("Calling adbg_CheckWindowClassName()\n", 2);
//            // Call adbg_CheckWindowClassName() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_CheckWindowClassName);
//            adbg_CheckWindowClassName();
//        }
//        else if (function == "NtSetInformationThread") {
//            log("Calling adbg_NtSetInformationThread()\n", 2);
//            // Call adbg_NtSetInformationThread() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_NtSetInformationThread);
//            adbg_NtSetInformationThread();
//        }
//        else if (function == "DebugActiveProcess") {
//            log("Calling adbg_DebugActiveProcess()\n", 2);
//            // Call adbg_DebugActiveProcess() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_DebugActiveProcess);
//            adbg_DebugActiveProcess(argv[1]);
//        }
//        else if (function == "QueryPerformanceCounter") {
//            log("Calling adbg_QueryPerformanceCounter()\n", 2);
//            // Call adbg_QueryPerformanceCounter() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_QueryPerformanceCounter);
//            adbg_QueryPerformanceCounter();
//        }
//        else if (function == "GetTickCount") {
//            log("Calling adbg_GetTickCount()\n", 2);
//            // Call adbg_GetTickCount() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_GetTickCount);
//            adbg_GetTickCount();
//        }
//        else if (function == "HardwareDebugRegisters") {
//            log("Calling adbg_HardwareDebugRegisters()\n", 2);
//            // Call adbg_HardwareDebugRegisters() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_HardwareDebugRegisters);
//            adbg_HardwareDebugRegisters();
//        }
//        else if (function == "MovSS") {
//            log("Calling adbg_MovSS()\n", 2);
//            // Call adbg_MovSS() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_MovSS);
//            adbg_MovSS();
//        }
//        else if (function == "CloseHandleException") {
//            log("Calling adbg_CloseHandleException()\n", 2);
//            // Call adbg_CloseHandleException() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_CloseHandleException);
//            adbg_CloseHandleException();
//        }
//        else if (function == "SingleStepException") {
//            log("Calling adbg_SingleStepException()\n", 2);
//            // Call adbg_SingleStepException() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_SingleStepException);
//            adbg_SingleStepException();
//        }
//        else if (function == "Int3") {
//            log("Calling adbg_Int3()\n", 2);
//            // Call adbg_Int3() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_Int3);
//            adbg_Int3();
//        }
//        else if (function == "PrefixHop") {
//            log("Calling adbg_PrefixHop()\n", 2);
//            // Call adbg_PrefixHop() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_PrefixHop);
//            adbg_PrefixHop();
//        }
//        else if (function == "Int2D") {
//            log("Calling adbg_Int2D()\n", 2);
//            // Call adbg_Int2D() implementation
//            PrintInstructionsInsideFunction((uintptr_t)adbg_Int2D);
//            adbg_Int2D();
//        }
//        else {
//            std::cout << "Invalid function specified. Use --help for usage." << std::endl;
//            return 1;
//        }
//    }
//    else {
//        std::cout << "Function not specified. Use --help for usage." << std::endl;
//        return 1;
//    }
//
//    return 0;
//}
//
//

int main(int argc, char* argv[]) {
    cxxopts::Options options("Ludus", "In Ancient Rome, a \"ludus\" referred to a training school for gladiators. Gladiators were combatants who fought in arenas as a form of entertainment. These schools, or ludus, were where gladiators were trained, equipped, and prepared for their battles in the arenas.");

    options.add_options()
        ("h,help", "Show help")
        ("f,function", "Function to call", cxxopts::value<std::string>())
        ;

    options.parse_positional({ "function" });

    std::vector<void (*)()> functions;
    functions.push_back(adbg_IsDebuggerPresent);
    functions.push_back(adbg_CheckRemoteDebuggerPresent);
    functions.push_back(adbg_ProcessFileName);
    functions.push_back(adbg_CheckWindowClassName);
    functions.push_back(adbg_NtSetInformationThread);
    functions.push_back(adbg_QueryPerformanceCounter);
    functions.push_back(adbg_GetTickCount);
    functions.push_back(adbg_HardwareDebugRegisters);
    functions.push_back(adbg_MovSS);
    functions.push_back(adbg_CloseHandleException);
    functions.push_back(adbg_SingleStepException);
    functions.push_back(adbg_Int3);
    functions.push_back(adbg_PrefixHop);
    functions.push_back(adbg_Int2D);

    std::string functionDescriptions[] = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "ProcessFileName",
        "CheckWindowClassName",
        "NtSetInformationThread",
        "QueryPerformanceCounter",
        "GetTickCount",
        "HardwareDebugRegisters",
        "MovSS",
        "CloseHandleException",
        "SingleStepException",
        "Int3",
        "PrefixHop",
        "Int2D"
    };

    options.custom_help("[options] [function]");
    options.add_options("Functions");
    std::cout << "Welcome to Ludus - Gladiator School of Debugger Evasion" << std::endl;
    std::cout << "Choose a function to call:" << std::endl;

    for (size_t i = 0; i < functions.size(); ++i) {
        std::cout << std::setw(2) << std::setfill('0') << i + 1 << ". " << functionDescriptions[i] << std::endl;
    }

    printf(">");
    int choice = -1;
    std::string userInput;
    std::getline(std::cin, userInput);

    if (!userInput.empty()) {
        try {
            choice = std::stoi(userInput) - 1;
        }
        catch (const std::invalid_argument& ex) {
            choice = -1;
        }
        // Simulate clearing the console by printing newlines
        for (int i = 0; i < 50; ++i) {
            std::cout << std::endl;
        }
        if (choice >= 0 && choice < static_cast<int>(functions.size())) {
            std::cout << "Calling " << functionDescriptions[choice] << "()" << std::endl;
            // Call the selected function implementation
            PrintInstructionsInsideFunction(reinterpret_cast<uintptr_t>(functions[choice]));
            functions[choice]();

         
        }
        else {
            std::cout << "Invalid function specified." << std::endl;
            return 1;
        }
    }
    else {
        std::cout << "No function selected." << std::endl;
        return 1;
    }

    return 0;
}