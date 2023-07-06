# POC-Mockingjay
Implementation of the Process Injection described in the article "Process Mockingjay : Echoing RWX In Userland To Achieve Code Execution" 

The particularity of this PE is to avoir EDR/AV hooking on typical WinAPI32 functions used for typical process injection.
Here, a DLL with already a RWX memory section is used to inject the shellcode.

Source : https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution

Thanks to the OnlyMalware Discord (cc ewby)

Shellcode : Pop a calc.exe
