# PrintNightmare_dll_check.ps1

A quick PowerShell script to recursively scan for unsigned dll in %windir%\system32\spool\drivers.
The scan path can be quickly changed within the script to any other location.

According to https://github.com/afwu/PrintNightmare a successful PrintNightmare attack places a malicious dll in %windir%\system32\spool\drivers.
These dll are most likely unsigned (neither AuthentiCode nor directly signed) but this approach will also show up false-positives as well.


Manual download of 3rd party tools
----------------------------------

For licensing reasons we can't provide the script fully operational including sigcheck64.exe.
Please manually download sigcheck64.exe from the offical Sysinternal website and place it next to PrintNightmare_dll_check.ps1.

|Download URL: | Extracted filename: |
| ------------ | ------------------- |
|https://download.sysinternals.com/files/Sigcheck.zip |	SigCheck64.exe |


Requirements
------------
1. Download of Sysinternals Sigcheck.zip
2. Extracting of sigcheck64.exe from Sigcheck.zip
3. local user rights (Admin permission NOT required)
4. Internet connection for external check of unsigned dll with Virustotal.com (or remove the sigcheck parameters '-v -vt' to stay local)


How to run
----------
1. place PrintNightmare_dll_check.ps1 to any directory where the executing user has write permission (e.g. C:\temp or C:\users\%username%\Documents)
2. place sigcheck64.exe next to PrintNightmare_dll_check.ps1 in the same directory
3. `cmd`
4. `powershell.exe -executionpolicy bypass C:\path_to\PrintNightmare_dll_check.ps1`


Returncode (%errorlevel%) of script
-----------------------------------
0 = NO unsigned dll found
1 = unsigned dll found -> check logfile for more details


Outputs of script
-----------------
logfile: C:\path_to\PrintNightmare_dll_check_YYYYMMDD-HHMM.txt
copy of unsigned dlls: C:\path_to\PrintNightmare_2nd_check_path\


Example of logfile - NO unsigned dll found
------------------------------------------
20210707-1142
script start

all dll files provide authenticode or are directly signed
NO suspicious dll files detetcted

script end


Example of logfile - unsigned dll found
---------------------------------------
20210707-1138
script start

dll files without authenticode nor directly signed:
Vix64AllProductsDyn.dll


Sigcheck v2.81 - File version and signature viewer
Copyright (C) 2004-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

c:\test\printnightmare_2nd_check_path\Vix64AllProductsDyn.dll:
	Verified:	Unsigned
	Link date:	14:15 30/04/2021
	Publisher:	n/a
	Company:	VMware, Inc.
	Description:	VMware application library
	Product:	VMware Workstation
	Prod version:	16.1.2 build-17966106
	File version:	16.1.2 build-17966106
	MachineType:	64-bit
	MD5:	22F4B8122EBE333200E833E05C2E357C
	SHA1:	B858B78C22ECCF9B7DA408C297BB53FAEFED6426
	PESHA1:	5F20D482AE71A3B78CCF39D98991E2DA6F14DB6F
	PE256:	35AE6215FEAA28DB3A2F4CD5111CE61747481162B013DFCE3377EC4BE9748D0F
	SHA256:	985E8F96133B794A66CB1AF894AC5ED509AC3DE4A54DB73FD85C96505CC5D890
	IMP:	9FB9711F21857F89F61E06F13A427CA8
	VT detection:	0/73
	VT link:	https://www.virustotal.com/gui/file/985e8f96133b794a66cb1af894ac5ed509ac3de4a54db73fd85c96505cc5d890/detection

script end


How to test the script
----------------------
Copy any unsigned dll from any local installed app (from C:\Program Files) to C:\Windows\System32\spool\drivers and run the script.
