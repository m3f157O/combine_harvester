# combine
Check your windows local security authority credential's safety with this awesome tool.

Coupled dump decoder @ https://github.com/ruggi99/combine-decoder

## Introduction

By readapting the safetydump rust library (many thanks to the author!!!), I have been able to EASILY bypass all the countermeasures put in place by most EDRs, except Kaspersky EDR, and TrendMicro (new detection, from a couple hours ago)

dbghelp!MiniDumpWriteDump with a custom callback could be used, until a year ago, to bypass most antivirus/EDR solutions. 


Now, most of them EASILY recognize statically or behaviorally the system API usage pattern, for programs written in languages such as  C++, Delphi and C#. 
(it could be possible anyway thanks to undocumented NtOpenProcessEx but that's another story) 


If you have a Go implementation, please give me feedback. I'm on it but still have some bugs related to memory size


I suspect that there is still no way to monitor the MiniDumpWriteDump callback, and all the protection against a possible credential dump via this technique is then entrusted to machine learning detections.





## Usage

### GUI
![image](https://github.com/m3f157O/combine_harvester/assets/79704302/89ad15f9-8366-45ca-a1b3-068724323e1f)


### CMD
![image](https://github.com/m3f157O/combine_harvester/assets/79704302/f033d48e-019e-4179-9b22-ad60e1552a7e)



### DECRYPT
![image](https://github.com/m3f157O/combine_harvester/assets/79704302/01665c76-248c-4b5e-a2ba-2b23d55b5288)


## References
Done thanks to  
- https://loong716.top/posts/lsass/
- https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass
- https://danielsauder.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-1-mimikatz-lsass-exe-dump/
- https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-credentials-from-lsass.exe-process-memory

Many code snippets are from
- https://github.com/postrequest/safetydump (very big help!!! thanks!!!)
- https://github.com/azazelm3dj3d/lsass-dump/blob/main/Dump/Dump.cpp
- https://rastamouse.me/dumping-lsass-with-duplicated-handles/

## Disclaimer
I am not responsible for any improper usage of this tool. This is meant for research and security testing purpose.

## Notes
The only effective mitigations (that I know of) against this sub-technique are RunAsPPL and CredentialGuard, but it's not always possible to enable these options.

