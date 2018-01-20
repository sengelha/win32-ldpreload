# Win32 LD\_PRELOAD

Many versions of UNIX have a useful concept built in to their dynamic
linker: by setting an environment variable (usually LD\_PRELOAD), a user
can force a shared library to load before all others. While I wasn’t
able to figure out how to exactly replicate this functionality on
Windows, I found a snippit on page 794 of *Programming Applications for
Microsoft Windows: Fourth Edition*, by Jeffrey Richter, on how to come
close. On this page, Mr. Richter explains a way to force an executable
to load a dynamic library before it begins executing code. While this is
only one of several ways he suggests to achieve this goal, I was drawn
to this one because it seemed the most flexible.

Mr. Richter entitles this method Injecting Code with CreateProcess.
Basically the idea is to actually change the code that the process will
execute, before the process even begins executing. By writing some
careful self-modifying code, you can add instructions to a process which
loads a library, then replaces the original instructions and begins
executing them as if nothing had happened.

This method can be extended to force a process to execute virtually any
instructions before it begins executing its original code. However, the
operating system security ensures you can only do this to processes for
which you have appropriate privileges (such as any processes that you
create).

This was a proof of concept written in 2001. Microsoft Research provides
a far more capable code injection application called Detours.
