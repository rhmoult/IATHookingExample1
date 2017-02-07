# IATHookingExample1
Simplest IAT Hooking example: Hook yourself!

This C/C++ code uses a technique introduced by Jeffrey Richter in Windows via C/C++ to hook the Import Address Table of a process.

Because this usually necessitates a custom DLL and DLL injection for best results, I've stripped it down to have the process hook
it's own IAT.

On exit, we have two options as to how to return.  We can find the real address of ExitProcess and ignore the IAT, or we can repair the IAT.

Note that many antivirus products do not appreciate this technique.  Be advised that your compiled program could get quarantined.

Enjoy!