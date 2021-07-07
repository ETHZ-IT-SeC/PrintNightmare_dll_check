# 2021-07-06 HV PrintNightmare dll check
# a quick script to recursively scan for unsigned dll in %windir%\system32\spool\drivers

# According to https://github.com/afwu/PrintNightmare a successful PrintNightmare attack places a malicious dll in %windir%\system32\spool\drivers
# These dll are most likely unsigned (neither AuthentiCode nor directly signed)

# VARIABLES
# printer directory where attacks with dll occur / malicious dll are planted
$srcpath = "$env:windir\system32\spool\drivers\*.dll"
# output directory where to copy unsigned dll for further check with Sysinternals sigcheck.exe
$2nd_check_path = "$PSScriptRoot\PrintNightmare_2nd_check_path"
# get current date / time
$now = Get-Date -Format "yyyyMMdd-HHmm"
# logfile name
$logfile = $PSScriptRoot + "\PrintNightmare_dll_check_" + $now + ".txt"

# create logfile
Add-Content -Path $logfile -Value $now -Encoding UTF8
Add-Content -Path $logfile -Value "script start" -Encoding UTF8
Add-Content -Path $logfile -Value "" -Encoding UTF8

# create further check directory
md $2nd_check_path

# search for unsigned dll (authenticode nor directly signed) and copy unsigned dll for further check
gci -Path $srcpath -Recurse | Get-AuthenticodeSignature | Where-Object {$_.Status -eq "NotSigned"} | cpi -Destination $2nd_check_path

# if unsigned dll are detected 
if (Test-Path $2nd_check_path\*.dll)
{
    $unsigned_dll_found=1
    # update logfile with name of unsigned dll(s)
    Add-Content -Path $logfile -Value "dll files without authenticode nor directly signed:" -Encoding UTF8
    gci $2nd_check_path | Add-Content -Path $logfile -Encoding UTF8
    Add-Content -Path $logfile -Value "" -Encoding UTF8
    # Check unsigned dll(s) with sigcheck and do external check with Virustotal.com; Internet connection required
    & $PSScriptRoot\sigcheck64.exe -accepteula -e -s -h -v -vt $2nd_check_path | Add-Content -Path $logfile -Encoding UTF8
    Add-Content -Path $logfile -Value "" -Encoding UTF8
}
else
{
    # otherwise if all dll are signed
    $unsigned_dll_found=0
    Add-Content -Path $logfile -Value "all dll files provide authenticode or are directly signed" -Encoding UTF8
    Add-Content -Path $logfile -Value "NO suspicious dll files detetcted" -Encoding UTF8
    Add-Content -Path $logfile -Value "" -Encoding UTF8
}
# update logfile
Add-Content -Path $logfile -Value "script end" -Encoding UTF8

# exit script; %errorcode% = 0 -> NO unsigned dll found; %errorcode% = 1 -> unsigned dll found!
EXIT $unsigned_dll_found