Function Get-OSSummary(){
    try{
        $ErrorActionPreference = "Stop"
        $osRelatedData = Get-WmiObject win32_OperatingSystem
        $licenseDetails = Get-WmiObject SoftwareLicensingProduct | Where-Object{$_.Name -like "Windows*" -and $_.PartialProductKey} | Select -ExpandProperty LicenseStatus



        $result = "" | Select-Object @{n="Machine_Name"; e={hostname}}, `
                                     @{n="Name"; e={$osRelatedData | Select -ExpandProperty Name }},`
                                     @{n="Version"; e={$osRelatedData | Select -ExpandProperty Version}},`
                                     @{n="Build_Number"; e={$osRelatedData | Select -ExpandProperty BuildNumber}},`
                                     @{n="NumberOfLicensedUsers"; e={$osRelatedData | Select -ExpandProperty NumberOfLicensedUsers}}, `
                                     @{n="LicenseStatus"; e={$licenseDetails}}, `
                                     @{n=’LastBootUpTime’;e={$osRelatedData | Select @{LABEL=’LastBootUpTime’;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}} | Select -ExpandProperty LastBootUpTime}}
        return $result
    }

    catch{
        return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
    }
} # Get OS Summary Details

Function Get-WindowsUpdateState {
    try{
        $ErrorActionPreference = "Stop"
        If (((Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv\").Start) -eq 4)
        {

        $WindowsUpdateStatus = $False
        $finalOutput = ""

        $WUpdateSrvState="bad"; 
        $finalOutput += "`nWindows Update Service is disabled.";
        } 
        else {
        $WUpdateSrvState="good";
        $finalOutput += "`nWindows Update Service is not disabled.";
        }
        
        
        If (((Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS\").Start) -eq 4)
        {
        $BitsSrvState="bad";
        $finalOutput += "`nBackground Intelligent Transfer Service is disabled.";
        } 
        else {
        $BitsSrvState="good"
        $finalOutput += "`nBackground Intelligent Transfer Service is not disabled.";
        }
        
        
        If (($WUpdateSrvState -eq "good") -and ($BitsSrvState -eq "good"))
        {
        $ServiceState="good";
        $finalOutput += "`nService State is good.";
        } 
        else {
        $ServiceState="bad"
            If ($WUpdateSrvState -eq "bad")
            {
                $finalOutput += "`nPlease enable Windows Update Service."
            }
            If ($BitsSrvState -eq "bad")
            {
                $finalOutput += "`nPlease enable Background Intelligent Transfer Service."
            }
            
        }
  
        $SystemName=$env:COMPUTERNAME
        $WinUpdSession=[System.Activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$SystemName)) 
        $WinUpdSearch=$WinUpdSession.CreateUpdateSearcher()
        $WinUpdResult=$WinUpdSearch.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0")
        If ($($WinUpdResult.Updates | ?{$_.MsrcSeverity -like "Important"}))
        {
        $WindowsUpdateStatus = $False
        $PatchState="bad"
        $WinUpdatesToInstall=($WinUpdResult.Updates | Select-Object Title)
        $WinUpdatesCategory=($($WinUpdResult.Updates).Categories | Select-Object Name)
        $WinUpdatesSeverity=($WinUpdResult.Updates | Select-Object MSRCSeverity)
        $finalOutput += "`nNumber of pending Windows Updates to Install: $($WinUpdResult.Updates.Count)" 
        $finalOutput += "`n`nList of pending Windows Updates to Install:"
        $finalOutput += $WinUpdResult.Updates | Select Title, MSRCSeverity, Description | Format-List | Out-String

        } 
        else {
        $WindowsUpdateStatus = $true
        $PatchState="good";
        $finalOutput += "`nNo pending Windows Updates to Install."
        }
        
        $PostUpdateReboot=New-Object -com Microsoft.Update.SystemInfo
        $RebootPendingState=$PostUpdateReboot.RebootRequired
        If ($RebootPendingState -eq "true")
        {
        $WindowsUpdateStatus  = $False
        $finalOutput += "`nSystem Reboot Pending. Please Reboot System."
        } 
        else {
        $finalOutput += "`nNo System Reboot Pending."
        }
        
        return @{"Result"=@($WindowsUpdateStatus, $finalOutput)}
    
    }

    catch{
        return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
    }

} # Get Windows Update Status

Function Get-LoggedInUser(){
    try{
        $ErrorActionPreference = "Stop"
        $users = (query user) -split "\n" -replace '\s\s+', ';' | convertfrom-csv -Delimiter ';' | Select USERNAME, STATE

        $result = @{"Result"=$users}

        return $result
    }
    catch{
        return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
    }
} # Get Details of logged in Users

Function Get-DriveDetails(){
    try{
        $driveDetails = Get-WmiObject win32_logicalDisk

        $result = $driveDetails | Select @{n="DeviceID";e={$driveDetails | Select -ExpandProperty DeviceID}}, `
                                         @{n="FreeSpace";e={"$($([math]::Round($($($driveDetails | Select -ExpandProperty FreeSpace)/$($driveDetails | Select -ExpandProperty Size)), 2))*100)%"}}
        return @{"Result"=$result}
    
    }

    catch{
        return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
    }
} # Get Driver Details

Function Get-HardwareInfo(){
    try{
     $ErrorActionPreference = "Stop"
     $hardwareDetails = Get-WmiObject Win32_ComputerSystem
     $result = $hardwareDetails | Select Manufacturer, Model, Name, NumberOfLogicalProcessors, NumberOfLogicalProcessors, SystemType
     
     return @{"Result"=$result}        
    }
    catch{
        return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
    }
} # Get hardware related Info

Function Get-AppInfo(){
    try{
        $ErrorActionPreference = "Stop"
        $appInfo = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 

        return @{"Result"=$appInfo}
    }

    catch{
        return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
    }
} # Get all the installed apps



try{
    $osSummary = Get-OSSummary
    $updateInfo = Get-WindowsUpdateState
    $loggedInUser = Get-LoggedInUser
    $hardwareInfo = Get-HardwareInfo
    $appInfo = Get-AppInfo

    $result = @{
        "OSSummary"=$osSummary;
        "UpdateInfo" = $updateInfo;
        "LoogedInUser"=$loggedInUser;
        "HardwareInfo"=$hardwareInfo;
        "AppInfo"=$appInfo
    } | ConvertTo-Json

}

catch{
    return @{"Result"="Error"; "ErrorMessage"="[MSG: ERROR : $($_.Exception.message)]"}
}