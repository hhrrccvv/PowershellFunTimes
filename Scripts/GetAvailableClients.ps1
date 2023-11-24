#Checks a list of computers for online clients that have no one logged in. 
#Can be used when you need to remote in to a device during school hours.
#Ryan Mock
#v1.0 - November 16, 2022
#v1.1 - January 16, 2023 (added input validation/error checking)
#v1.2 - March 29, 2023 (fixed error when selecting specific devices)
#v1.3 - June 12, 2023 (added WoL functionality based on Matthew Derksens script)
#v1.4 - October 18, 2023 (added...flair...)
#v1.5 - November 17, 2023 (added progress bars and forced admin)

param(
[switch]$Elevated, #Makes sure powershell is running as admin
[Parameter(ValueFromPipeline=$true)]
[String[]]$x
)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent()) #Checks if 
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -ExecutionPolicy Bypass -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

'Running with full privileges'

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

#Variables (set to null at the start to avoid any contamination)
$_userRoute = $null #holds the choice of prefix or list
$_clientsToCheck = $null #holds a user provided list of devices
$_prefix = $null #holds the beginning of the computer names
$_devices = $null #holds the list of devices found in MECM
$_onlineDevices = $null #holds the list of devices that are online
$_loggedOn = $null #holds the username of whoever is logged in
$_onlineAvailableDevices = $null #holds the list of devices that are online and open for login
$_remoteChoice = $null #holds the user choice 
$_remoteAmount = $null #holds how many computers the user chooses to remote into
$_specificDevice = $null #holds the user choice of specific device(s) or not
$_userPrefDevices = $null #holds the users choice of devices to connect to
$_userPrefDevicesList = $null #holds the list of users chosen devices to connect to
$_attempt = $null #holds results for try-catch
$_preExit = $null #holds a result if the user exits a prompt without providing input

$Host.UI.RawUI.WindowTitle = "Getting available clients..."

if(Test-Path SD3:) #Checks if the MECM module has already been imported
{
    echo "Module found, continuing..."
    echo `n #Inserts a blank line
}
else #If the MECM module is not found
{
    echo "Module not found, importing..."
    echo "Module imported, continuing..."
    echo `n
    
    cd "$env:SMS_ADMIN_UI_PATH\..\"
    Import-Module .\ConfigurationManager.psd1 #Imports the MECM module for use
}

Install-Module -Name WriteAscii -RequiredVersion 1.2.2 #Installs the Ascii module because that seemed...necessary...
Install-Module -Name PsoProgressButton

do{
    #Creates a new folder for text files, and text files for the script to use
    New-Item -Path C:\Temp\GetClients\ -ItemType Directory -Force 
    New-Item -Path C:\Temp\GetClients\ListedClients.txt -ItemType File -Force
    New-Item -Path C:\Temp\GetClients\AvailableClient.txt -ItemType File -Force
    New-Item -Path C:\Temp\GetClients\OnlineClients.txt -ItemType File -Force
    New-Item -Path C:\Temp\GetClients\OpenClients.txt -ItemType File -Force
    New-Item -Path C:\Temp\GetClients\UserPrefClients.txt -ItemType File -Force

    $_repeatChoice = $null #holds a result of the user choice to run the program again. Put here to reset every time the script loops to avoid infinite loops.

    Push-Location SD3: #Changes directory to the MECM site

    do{    
        $_userRoute = Read-Host -Prompt "`nWould you like to use a list of devices or a group of prefixes such as INFO-TECH-WXXX? (list/prefix)" #Asks the user to either read a text file or run from a prefix
    }while($_userRoute -notlike "l*" -and $_userRoute -notlike "p*") #Verifies a valid choice has been made

    if($_userRoute -like "l*") #If the user chose lists
    {
        do{
            C:\Temp\GetClients\ListedClients.txt #Opens the text file to be filled with a list

            Read-Host -Prompt "Please enter the names of the devices you want to check. Save and close the file, and press 'Enter' to continue."
    
            $_clientsToCheck = Get-Content -Path C:\Temp\GetClients\ListedClients.txt #Takes in the user provided list of devices

            if($_clientsToCheck -eq $null) #Checks the text file and informs the user if it's empty
            {
                echo "You didn't enter anything, please try again."
                echo `n
            }
        }while($_clientsToCheck -eq $null) #Checks that there's information in the text file to read, if not, restarts the loop
    
        foreach($_client in $_clientsToCheck) #loops through the entire list one by one
        {        
            Get-CMDevice -Name $_client | sort Name | select -ExpandProperty Name | Add-Content -Path C:\Temp\GetClients\AvailableClient.txt #Finds devices in MECM matching the given prefix
        }
    }
    elseif($_userRoute -like "p*") #If the user chose prefixes
    {    
        do{
            $_prefix = Read-Host -Prompt "What is the prefix you're looking for? I.e. 'INFO-TECH' (the program will add -WXXX) " #Takes in a prefix of devices (i.e. INFO-TECH)

            if($_prefix.Length -gt 9 -and $_prefix -notlike "*-*") {
                echo "You've entered too many characters, or incorrectly formatted the prefix, please try again" #Checks if the user has entered more than 9 or used the wrong format and informs them
            }
        }while($_prefix.Length -gt 9)#Validates the user hasn't entered too many characters

        $Host.UI.RawUI.WindowTitle = "Getting availble clients from $_prefix"

        echo `n    
        Get-CMDevice -Name "$_prefix*" | sort Name | select -ExpandProperty Name | Out-File -FilePath C:\Temp\GetClients\AvailableClient.txt -Force #Finds devices in MECM matching the given prefix
    }

    $_devices = Get-Content C:\Temp\GetClients\AvailableClient.txt

    echo "Matching devices found: " #Outputs the list of devices found to the screen
    echo $_devices | Out-Host
    echo `n

#######################################################WakeOnLanInclusion#####################################################################################################################################

#### Confirm AD commands will work
if (get-command get-adcomputer -ErrorAction SilentlyContinue){}
else {
    Write-host -ForegroundColor Red "Active Directory commands failed"
    Write-host "Checking for Rsat.ActiveDirectory.DS-LDS.Tools..."
    try {
        if ($(Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0").State -ne "Installed") {
            Write-Host -ForegroundColor Red -NoNewline "ActiveDirectory & LDS Tools were not detected. "
            Write-Host "Would you like to install them now?"
            Switch (Read-Host -Prompt "Y or N"){
                "Y" {
                    try {Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”}
                    Catch [System.Runtime.InteropServices.COMException] {
                        Write-Host -ForegroundColor Red "The requested operation requires elevation."
                        }
                    Catch {Write-Host -ForegroundColor red "ERROR"}
                    }
                "N" {
                    Start-Sleep -Seconds 1
                    Exit
                    }
                }
            }
        }
    Catch [System.Runtime.InteropServices.COMException] {
        Write-Host -ForegroundColor Red "The requested operation requires elevation."
        Read-host -Prompt "Exiting..."
        Exit
        }
    Catch {Write-Host -ForegroundColor red "ERROR"
        Read-host -Prompt "Exiting..."
        Exit
        }
    }

Push-Location

#### Define variable using parameter ###########################
[System.Collections.ArrayList]$_ComputerList = @($_devices)

#### Remove Blanks & Doubles ###############################
[System.Collections.ArrayList]$_ComputerList = @($_ComputerList -ne "" | Sort -Unique)

#### Exit if no computers listed ###############################
if ($_ComputerList.Count -eq 0 -or -not $_ComputerList) {Pop-Location; Return}

#### Connect to SCCM Site ######################################
    # Site configuration
    $SiteCode = "SD3" # Site code 
    $ProviderMachineName = "SD36-CM11.sd36.bc.ca" # SMS Provider machine name

    # Customizations
    $initParams = @{}
    #$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
    #$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

    # Do not change anything below this line

    # Import the ConfigurationManager.psd1 module 
    if((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
    }

    # Connect to the site's drive if it is not already present
    if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
    }

    # Set the current location to be the site code.
    Set-Location "$($SiteCode):\" @initParams
################################################################

$_CMResource = @()
####Import Cache
$_NonCache = @()
If (Test-Path -Path $env:APPDATA\WOLCache.xml) {
    $_WOLCache = @(Import-Clixml -Path $env:APPDATA\WOLCache.xml)
    Write-Progress -Activity "Checking Cache..." -Status "0 / $($_ComputerList.Count)" -PercentComplete (0 / $($_ComputerList.Count)*100)
    $_ComputerList + $($_WOLCache | Select -ExpandProperty Name |foreach {If ($_ -in $_ComputerList) {$_}}) | Group | Foreach {
        Write-Progress -Activity "Checking Cache..." -Status "$($_ComputerList.Indexof($_.Name))/ $($_ComputerList.Count)" -PercentComplete ($($_ComputerList.Indexof($_.Name)) / $($_ComputerList.Count)*100)
        If ($_.count -gt 1) {
            $_CMResource += $_WOLCache | Where Name -eq $_.Name
            }
        If ($_.Count -le 1) {
            If ($_ComputerList -contains $_.Name){
                $_NonCache += @($_.Name)
                }
            }
        }
    Write-Progress -Completed -Activity "Checking Cache..."
    }
Else {
    $_WOLCache = @()
    $_NonCache = $_ComputerList
    }

####Pull MECM Data
IF ($_NonCache.count -gt 0) {
    Write-Progress -Activity "Gathering machine info from MECM..." -Status "0 / $($_NonCache.Count)" -PercentComplete (0 / $($_NonCache.Count)*100)
    $_CMResource += Foreach ($_Computer in $_NonCache) {
        $_ResourceID = Get-cmdevice -Fast -Name $_Computer | Select -ExpandProperty ResourceID
        $_ResourceOutput = If ($_ResourceID -ne $null) {$_ResourceID | Foreach {Get-CMResource -fast -ResourceType System -ResourceId $_ | select MACAddresses, IPAddresses, Name, ResourceId}}
        If ($($_ResourceOutput.MACAddresses) -ne $null) {
            $_WOLCache += $_ResourceOutput
            $_WOLCache | Export-Clixml $env:APPDATA\WOLCache.xml
            }
        $_ResourceOutput
        Write-Progress -Activity "Gathering machine info from MECM..." -Status "$($_NonCache.IndexOf($_computer)) / $($_NonCache.Count)" -PercentComplete ($($_NonCache.IndexOf($_computer)) / $($_NonCache.Count)*100)
        }

    Write-Progress -Completed -Activity "Gathering machine info from MECM..."
    }

####Pull AD Data
$_ADResource = @{}
Write-Progress -Activity "Gathering machine info from Active Directory..." -Status "0 / $($_ComputerList.Count)" -PercentComplete (0 / $($_ComputerList.Count)*100)
Foreach ($_Computer in $_ComputerList) {
    If (Get-ADComputer -Filter "Name -eq '$_Computer'") {
        $_ADResource[$_Computer] = $True
        } 
    Else {
        $_ADResource[$_Computer] = $False
        }
    Write-Progress -Activity "Gathering machine info from Active Directory..." -Status "$($_ComputerList.IndexOf($_computer)) / $($_ComputerList.Count)" -PercentComplete ($($_ComputerList.IndexOf($_computer)) / $($_ComputerList.Count)*100)
    }
Write-Progress -Completed "Gathering machine info from Active Directory..."

####Pull Network Data
$_ObjArray = @()
$_Jobs = 

$_SiteServers = @()
$($(Get-ADDomainController -filter * | select -ExpandProperty Hostname) + $(Get-ADComputer -Filter 'Name -like "*-FS1"' -SearchBase "OU=Servers,OU=_IMS,DC=sd36,DC=bc,DC=ca" | Select -ExpandProperty DNSHostName)).split(".") -like "????-??1" | Sort | Group-Object {$_.split("-")[0]} | Foreach {
    If ($_.Count -eq 1) {$_SiteServers += $_.Group}
    If ($_.Count -gt 1) {$_SiteServers += $_.Group[0]}
    }
$_SiteServers = $_SiteServers -notlike "TEST-*" -notlike "DEVT-*" -notlike "DR02-*"

Write-Progress -Activity "Retrieving info from the Network..." -Status "$($(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count) / $($_ComputerList.Count)" -PercentComplete ($($(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count)/$($_ComputerList.Count)*100)
Foreach ($_Computer in $_ComputerList) {
    $_Running = Get-Job | Where-Object { $_.State -eq 'Running' }
    If ($_Running.Count -le 20) {
        $_Jobs += Start-job -Name $_Computer -ScriptBlock {
            $_CurrentUser = $null
            $_ExistsOn = @()
            $_TempIp = @()
            $_TempMac = @()
            #MECM
            $_CMDevice = $Args[1] | Where Name -EQ $Args[0]
            IF (-Not [string]::IsNullOrEmpty($_CMDevice)){$_ExistsOn += "SCCM"}
            $_CMDevice.IPAddresses | Foreach {$_TempIP += "$_"}
            $_CMDevice.MACAddresses | Foreach {
                if (-Not [string]::IsNullOrEmpty($_)) {
                    $_TempMac += "$_"
                    }
                }
            #DNS
            $_TempDnsName = $false
            Try {Resolve-DNSName -Name $Args[0] -ErrorAction stop | Select -ExpandProperty IPAddress | Foreach {$_TempIP += "$_"}
                $_TempDnsName = $True}
            Catch {}
            If ([BOOL]($Args[3] -contains ($Args[0].Split("-")[0] + "-DC1"))) {
                Try {Resolve-DnsName -Name $Args[0] -Server ($Args[0].Split("-")[0] + "-DC1") -ErrorAction stop | Select -ExpandProperty IPAddress | Foreach {$_TempIP += "$_"}
                    $_TempMac += (Get-DHCPServerv4Lease -scopeid (($_TempIP[-1].split(".")[0..2] -join '.') + ".0") -computername ($Args[0].Split("-")[0] + "-DC1") | where IPaddress -like $_TempIP[-1] | Select -ExpandProperty ClientId).replace("-",":").ToUpper()
                    $_TempDnsName = $True}
                Catch {}
                }
            ElseIf ([BOOL]($Args[3] -contains ($Args[0].Split("-")[0] + "-FS1"))) {
                Try {Resolve-DnsName -Name $Args[0] -Server ($Args[0].Split("-")[0] + "-FS1") -ErrorAction stop | Select -ExpandProperty IPAddress | Foreach {$_TempIP += "$_"}
                    $_TempMac += (Get-DHCPServerv4Lease -scopeid (($_TempIP[-1].split(".")[0..2] -join '.') + ".0") -computername ($Args[0].Split("-")[0] + "-FS1") | where IPaddress -like $_TempIP[-1]| Select -ExpandProperty ClientId).replace("-",":" ).ToUpper()
                    $_TempDnsName = $True}
                Catch {}
                }
            Else {
                Try {Resolve-DnsName -Name $Args[0] -Server SD36-DC3 -ErrorAction Stop | Select -ExpandProperty IPAddress | Foreach {$_TempIP += "$_"}
                    $_TempMac += (Get-DHCPServerv4Lease -scopeid (($_TempIP[-1].split(".")[0..2] -join '.') + ".0") -computername SD36-DC3 | where IPaddress -like $_TempIP[-1] | Select -ExpandProperty ClientId).replace("-",":" ).ToUpper()
                    $_TempDnsName = $True}
                Catch {}
                }
            if ($_TempDnsName -eq $True) {$_ExistsOn += "DNS"}
            #LAN
            $_TempIP = $_TempIP | Where-Object { $_ -notlike "*:*" }
            If (Test-Connection $Args[0] -count 1 -ErrorAction ignore) { 
                $_Status = "Online"
                Try {$_CurrentUser = Get-CimInstance -Shallow -OperationTimeoutSec 5 -ErrorAction Stop –ComputerName $Args[0] -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName}
                Catch [System.Runtime.InteropServices.COMException] {
		            $_CurrentUser = "ERROR: RPC Server is unavailable"
	                }
	            Catch [System.Management.ManagementException] {
		            $_CurrentUser = "ERROR: Access Denied"
	                }
	            Catch [System.UnauthorizedAccessException] {
		            $_CurrentUser = "ERROR: Unauthorized Access"
	                }
                Catch {
                    $_CurrentUser = "ERROR"
                    }
                $_ExistsOn += "LAN"
                }
            Else { $_Status = "Offline" }
            New-Object -TypeName PSObject -Property @{
                Name = $Args[0]
                MACAddresses = $_TempMac
                IP = $_TempIP
                Status = $_Status
                WasWoke = $null
                CurrentUser = $_CurrentUser
                ExistsOn = $_ExistsOn
                InAD = $Args[2]
                }
            } -Argumentlist $_Computer,$_CMResource,$_ADResource.$_Computer,$_SiteServers
        Write-Progress -Activity "Retrieving info from the Network..." -Status "$($(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count) / $($_ComputerList.Count)" -PercentComplete ($($(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count)/$($_ComputerList.Count)*100)
        }
    Else {
        While ($(Get-Job | Where-Object { $_.State -eq 'Running' }).count -gt 20){
            Write-Progress -Activity "Retrieving info from the Network..." -Status "$($(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count) / $($_ComputerList.Count)" -PercentComplete ($($(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count)/$($_ComputerList.Count)*100)
            Start-sleep -Seconds 1
            }
        }
    }

$_JobOutput = $_Jobs | Receive-Job -AutoRemoveJob -wait
Write-Progress -Completed -Activity "Retrieving info from the Network..."

#### Final Array cleanup
Foreach ($_Obj in $_JobOutput) {
    $_Obj.IP = $_Obj.IP | Select -Unique | Where {$_ -ne ""}
    $_Obj.MACAddresses =  $_Obj.MACAddresses | Select -Unique | Where {($_ -ne "") -and ($_ -ne $null)}
    IF ($_Obj.ExistsOn.count -eq 0) {
        Write-Host -ForegroundColor Red -NoNewline "$($_Obj.Name)"
        Write-host " does not Exist in SCCM, on a DNS server, or on the LAN"
        $_JobOutput = $_JobOutput | Where-Object {$_JobOutput.Name -ne $_Obj.Name}
        }
    }

If ($_JobOutput.count -ne 0) {
    function Send-Magic {
        Write-host "Sending Magic Packets..."
        #### Wake-on-LAN fuction #######################################
        function Send-WOL { 
            param( 
                [Parameter(Mandatory=$True,Position=1,ValueFromPipeline=$True)] 
                [ValidatePattern('(^([0-9a-fA-F]{2}[\.:-]{0,1}){5}[0-9a-fA-F]{2}$)|(^([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})$)')] 
                [string]$mac, 
                [string]$ip,
                [string]$Name, 
                [int]$port=9 
                ) 
            $broadcast = [Net.IPAddress]::Parse($ip) 
 
            $OutMac = $null
            $mac=(($mac.replace(":","")).replace("-","")).replace(".","")
            $target=0,2,4,6,8,10 | % {[convert]::ToByte($mac.substring($_,2),16)}
            $packet = (,[byte]255 * 6) + ($target * 16)
 
            $UDPclient = new-Object System.Net.Sockets.UdpClient 
            $UDPclient.Connect($broadcast,$port) 
            [void]$UDPclient.Send($packet, 102) 
            }

        Foreach ($_Obj in $_JobOutput) {
        #### Send Magic Packet
            IF ($_Obj.MACAddresses -ne ""){
                Foreach ($_Mac in $_Obj.MACAddresses) {
                    Foreach ($_IP in $_Obj.IP) {
                        If (-not [String]::IsNullOrEmpty($_IP)) {
                            Send-Wol -mac $_MAC -ip $_IP -Name $_Obj.Name
                            ###NRD Wake-On-Lan Subnet
                            $_NRDip = ($_IP.split(".")[0..1] -join ".") + ".242.255"
                            Send-Wol -mac $_MAC -ip $_NRDip -Name $_Obj.Name
                            }
                        }
                    }
                }
            }
        }
    Send-Magic

    #### Wait for machines to fully wake up
    Start-Sleep -Seconds 5

    function Online-Check{
        $_OnlineStatus = $_JobOutput.Name | Foreach {Test-Connection -ComputerName $_ -Count 2 -AsJob} | Get-job | Receive-Job -Wait -AutoRemoveJob
        Foreach ($_Obj in $_JobOutput){
            if (($_OnlineStatus | Where Address -eq $_Obj.Name).StatusCode -eq 0) {
                If ($_Obj.Status -eq "Offline") {
                    $_Obj.WasWoke = $true
                    }
                $_Obj.Status = "Online"
                if ($_Obj.ExistsOn -notcontains "LAN") {
                    $_Obj.ExistsOn += "LAN"
                    }
                }
            else {
                $_Obj.Status = "Offline"
                }
            }
        }
    Online-Check

    #### Display results
    function Display-Results {
        #$_JobOutput | Sort-Object status, WasWoke, name | Format-table -Property Name, CurrentUser, WasWoke, Status, ExistsOn
        $_JobOutput | Sort Status,Name | Format-table Name,CurrentUser,WasWoke,@{
            Label = "Status"
            Expression = 
                {
                Switch ($_.Status)
                    {
                    'Online' { $color = "92"; break }
                    'Offline' { $color = "91"; break }
                    }
                $e = [char]27
                "$e[${color}m$($_.Status)${e}[0m"
                }
            },ExistsOn
        }
    Display-Results
    }

     Function Run-SCCMClientAction {
        [CmdletBinding()]
        # Parameters used in this function
        param
        (   [Parameter(Position=0, Mandatory = $True, HelpMessage="Provide server names", ValueFromPipeline = $true)] 
            $Computername,
 
            [ValidateSet('MachinePolicy', 
                        'DiscoveryData', 
                        'ComplianceEvaluation', 
                        'AppDeployment',  
                        'HardwareInventory', 
                        'UpdateDeployment', 
                        'UpdateScan', 
                        'SoftwareInventory')] 
            [string[]]$ClientAction
        ) 

        function Send-WOL { 
            param( 
                [Parameter(Mandatory=$True,Position=1,ValueFromPipeline=$True)] 
                [ValidatePattern('(^([0-9a-fA-F]{2}[\.:-]{0,1}){5}[0-9a-fA-F]{2}$)|(^([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})$)')] 
                [string]$mac, 
                [string]$ip,
                [string]$Name, 
                [int]$port=9 
                ) 
            $broadcast = [Net.IPAddress]::Parse($ip) 
 
            $OutMac = $null
            $mac=(($mac.replace(":","")).replace("-","")).replace(".","")
            $target=0,2,4,6,8,10 | % {[convert]::ToByte($mac.substring($_,2),16)}
            $packet = (,[byte]255 * 6) + ($target * 16)
 
            $UDPclient = new-Object System.Net.Sockets.UdpClient 
            $UDPclient.Connect($broadcast,$port) 
            [void]$UDPclient.Send($packet, 102) 
            }

        $ActionResults = @()
        $ComputerName | Foreach {
            IF ($_.MACAddresses -ne ""){
                Foreach ($_Mac in $_.MACAddresses) {
                    Foreach ($_IP in $_.IP) {
                        If (-not [String]::IsNullOrEmpty($_IP)) {
                            Send-Wol -mac $_MAC -ip $_IP -Name $_Obj.Name
                            ###NRD Wake-On-Lan Subnet
                            $_NRDip = ($_IP.split(".")[0..1] -join ".") + ".242.255"
                            Send-Wol -mac $_MAC -ip $_NRDip -Name $_Obj.Name
                            #Write-Host "$($_.name)"
                            }
                        }
                    }
                }
            Try { 
                    $ActionResults += Invoke-Command -AsJob -ComputerName $_.Name {param($ClientAction)
 
                            Foreach ($Item in $ClientAction) {
                                $Object = @{} | select "Action name",Status
                                Try{
                                    $ScheduleIDMappings = @{ 
                                        'MachinePolicy'        = '{00000000-0000-0000-0000-000000000021}'; 
                                        'DiscoveryData'        = '{00000000-0000-0000-0000-000000000003}'; 
                                        'ComplianceEvaluation' = '{00000000-0000-0000-0000-000000000071}'; 
                                        'AppDeployment'        = '{00000000-0000-0000-0000-000000000121}'; 
                                        'HardwareInventory'    = '{00000000-0000-0000-0000-000000000001}'; 
                                        'UpdateDeployment'     = '{00000000-0000-0000-0000-000000000108}'; 
                                        'UpdateScan'           = '{00000000-0000-0000-0000-000000000113}'; 
                                        'SoftwareInventory'    = '{00000000-0000-0000-0000-000000000002}'; 
                                    }
                                    $ScheduleID = $ScheduleIDMappings[$item]
                                    Write-Verbose "Processing $Item - $ScheduleID"
                                    [void]([wmiclass] "root\ccm:SMS_Client").TriggerSchedule($ScheduleID);
                                    $Status = "Success"
                                    Write-Verbose "Operation status - $status"
                                }
                                Catch{
                                    $Status = "Failed"
                                    Write-Verbose "Operation status - $status"
                                }
                                $Object."Action name" = $item
                                $Object.Status = $Status
                                $Object
                            }
 
                    } -ArgumentList $ClientAction -ErrorAction Stop | Select-Object @{n='ServerName';e={$_.pscomputername}},"Action name",Status
                }  
            Catch{
                Write-Error $_.Exception.Message
                }
            }  
        Get-job | Receive-Job -Wait -AutoRemoveJob
    } 

$_Answer = " "
While ($_Answer -ne $null) {
    $_Answer = $null
    $_Answer = @(
        New-Object -TypeName PSObject -Property @{
            Name="Rerun Wake-On-LAN"
            Discription="Resend magic packets"
            }
        New-Object -TypeName PSObject -Property @{
            Name="Verbose results"
            Discription="Displays verbose output"
            }
        New-Object -TypeName PSObject -Property @{
            Name="Aggressive IP ping"
            Discription="TESTING: Ping using every discovered IP, not just the first resolved DNS name"
            }
        New-Object -TypeName PSObject -Property @{
            Name="Export CSV"
            Discription="Exports results to CSV"
            }
        New-Object -TypeName PSObject -Property @{
            Name="Client Center"
            Discription="Opens Client Center for all online machines"
            }
        New-Object -TypeName PSObject -Property @{
            Name="MPREC (Beta)"
            Discription="Run Machine Policy on Online machines"
            }
        New-Object -TypeName PSObject -Property @{
            Name= "Continuous"
            Discription="Run Wake-On-Lan continuously until closed"
            }
        New-Object -TypeName PSObject -Property @{
            Name= "Delete Cache"
            Discription="Delete MECM Cache (Current size: $($_WOLCache.count) machines)"
            }
                ) | Select-Object Name,Discription | Out-GridView -OutputMode Single -Title Options
        
    Switch ($_Answer.Name){
        "Rerun Wake-On-LAN" { 
            Send-Magic
            Start-Sleep -Seconds 5
            Online-Check
            Display-Results
            }

        "Verbose results" {
            $_JobOutput | Sort-Object name | Format-table Name,CurrentUser,WasWoke,@{
                Label = "Status"
                Expression = 
                    {
                    Switch ($_.Status)
                        {
                        'Online' {$color = "92"; break}
                        'Offline' {$color = "91"; break}
                        }
                    $e = [char]27
                    "$e[${color}m$($_.Status)${e}[0m"
                    }
                },ExistsOn,@{
                    Label = "In AD"
                    Expression =
                    {
                    if ($($_.ExistsOn).Count -gt 0) {
                        if ($_.InAD -eq "True") {$color = "92"}
                        else {$color = "91"}
                        }
                    else  {$color = "91"}
                    $e = [char]27
                    "$e[${color}m$($_.InAD)${e}[0m"
                    }
                },IP,MACAddresses
            }

        "Aggressive IP ping" {
            Foreach ($_Computer in $_JobOutput){
                Foreach ($_IP in $_Computer.IP) {
                    Write-Host -NoNewLine "$($_Computer.Name)"
                    Write-Host -NoNewLine -ForegroundColor Gray " $_IP "
                    If (Test-Connection $_IP -Count 3 -Quiet) {
                        Write-Host -ForegroundColor Green "Online"
                        Foreach ($_Obj in $_JobOutput | where name -EQ $_Computer.Name  ){
                            $_Obj.Status = "Online"
                            }
                        }
                    Else {Write-Host -ForegroundColor Red " No reply"}
                    }
                }
            }

        "Export CSV" {
            $_OutputFolder = New-Object windows.forms.FolderBrowserDialog
            $_OutputFolder.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true})) | Out-Null
            If ($_OutputFolder.SelectedPath -eq $null) {
                $_OutputFolder.SelectedPath = [Environment]::GetFolderPath("Desktop")
                }
            $_OutputFolder = $_OutputFolder.SelectedPath
            
            $_Count = $null
            $_OutputName = "WOL_Output"
            While (Test-Path $("$_OutputFolder\$_OutputName" + "$_Count" + ".csv")){
                $_Count++
                If (-not (Test-Path $("$_OutputFolder\$_OutputName" + "$_Count" + ".csv"))) {
                    $_OutputName = "$_OutputName" + "$_Count"
                    Write-Host $_OutputName
                    Break
                    }
                }
            $_CSVOutput = $_JobOutput
            Foreach ($_Obj in $_CSVOutput) {
                If ($_Obj.IP.Count -gt 1) {
                    $_CSVOutput | Foreach{
                        If ($_.Name -eq $_Obj.Name) {
                            $_.IP = $_Obj.IP -join ', '
                            }
                        }
                    }
                If ($_Obj.MACAddresses.Count -gt 1) {
                    $_CSVOutput | Foreach{
                        If ($_.Name -eq $_Obj.Name) {
                            $_.MACAddresses = $_Obj.MACAddresses -join ', '
                            }
                        }
                    }
                }

            $_CSVOutput | Select-Object Name,CurrentUser,WasWoke,Status,ExistsOn,IP,MACAddresses | Export-CSV -Path $("$_OutputFolder\$_OutputName" + ".csv") -NoTypeInformation
            }

        "Client Center" {
            $_CliCtrLocation = $null
            If (Test-Path 'C:\Program Files\Zander Tools\Client Center for Configuration Manager\SCCMCliCtrWPF.exe') {$_CliCtrLocation = 'C:\Program Files\Zander Tools\Client Center for Configuration Manager\SCCMCliCtrWPF.exe'}
            If (Test-Path 'C:\Program Files\WindowsApps\30324RogerZander.ClientCenterforConfigurationManag_1.0.7.0_x64__a2sq1ntnxrqj8\VFS\ProgramFilesX86\Zander Tools\Client Center for Configuration Manager\SCCMCliCtrWPF.exe') {$_CliCtrLocation = 'C:\Program Files\WindowsApps\30324RogerZander.ClientCenterforConfigurationManag_1.0.7.0_x64__a2sq1ntnxrqj8\VFS\ProgramFilesX86\Zander Tools\Client Center for Configuration Manager\SCCMCliCtrWPF.exe'}
            If (Test-Path 'C:\Program Files\Client Center for Configuration Manager\SCCMCliCtrWPF.exe') {$_CliCtrLocation = 'C:\Program Files\Client Center for Configuration Manager\SCCMCliCtrWPF.exe'}
            If ($_CliCtrLocation -ne $null) {
                Send-Magic
                Start-Sleep -Seconds 5
                Write-Host -NoNewline "Checking Online Status..."
                Online-Check
                Write-Host "Done"
                Write-Host "Sending commands..."
            
                $_JobOutput | where status -eq "Online" | Foreach {Start $_CliCtrLocation $_.Name}
                }
            Else {
                Write-Host -ForegroundColor Red "Could not locate Client Center exe. Contact script creator!"
                }
            }

        "MPREC (Beta)" {
            Send-Magic
            Start-Sleep -Seconds 5
            Write-Host -NoNewline "Checking Online Status..."
            Online-Check
            Write-Host "Done"
            Write-Host "Sending commands..."
            Run-SCCMClientAction -Computername $($_JobOutput | where status -eq "Online") -ClientAction MachinePolicy | Select "Action name",Status,PSComputerName | Format-table PSComputerName,Status,"Action name"
            }

        "Delete Cache"{
            Remove-Item -Path $env:APPDATA\WOLCache.xml
            }

        "Continuous" {
            While ($True){
                Send-Magic
                Start-Sleep -Seconds 5
                Online-Check
                Display-Results
                }
            }
        }
    }

Pop-Location

#######################################################WakeOnLanInclusion#####################################################################################################################################

    foreach($_device in $_devices) #Loops through all matching devices found checking for online status
    {
        echo "Testing $_device..."
        $_iterator = 0
        $_testingCount = ($_iterator / $_devices.Count) * 100

        Set-PsoProgressButtonValue -CurrentValue $_iterator
    
        if(Test-Connection -ComputerName $_device -Count 1 -Quiet) #pings the device once and checks for a response
        {
            $_device | Add-Content C:\Temp\GetClients\OnlineClients.txt #adds the online client to the text file
        }

        $_iterator++
    }

    Set-PsoProgressButtonState -ProgressState NoProgress

    $_onlineDevices = Get-Content C:\Temp\GetClients\OnlineClients.txt #Puts all online devices into an array

    if($_onlineDevices -eq $null) #Checks if any of the devices are reachable
    {
        echo "None of the devices you've checked are online"

        do{
            $_repeatChoice = Read-Host -Prompt "Would you like to start over? (y/n)"
        }while($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks for a valid response
    }
    else #Continues running the script as long as one or more devices are online
    {
        foreach($_online in $_onlineDevices) #Loops through array of online devices, checking for a logged on user
        {
            $_loggedOn = Get-WmiObject -ComputerName $_online -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName #Gets the username of anyone logged into the device

            if(!$_loggedOn) #Triggers if no one is logged into the device
            {
                $_online | Add-Content C:\Temp\GetClients\OpenClients.txt #adds the available client to the text file
            }
            elseif($_loggedOn) #Triggers if a user is logged into the device
            {
                echo "$_loggedOn is currently logged on to $_online"
            }
        }

        $_onlineAvailableDevices = Get-Content C:\Temp\GetClients\OpenClients.txt #Puts online devices with no user logged on into an array

        echo `n
        echo "Devices that are online and available are shown below:" #Displays the array of online devices available for remoting into without disruption
        echo "v v v v v v"
        echo `n
        echo $_onlineAvailableDevices #Displays the list of available devices

        do{    
            $_remoteChoice = Read-Host -Prompt "Would you like to attempt to remote into the available devices? (Y/N)" #Asks if the user would like to remote into the devices
        }while($_remoteChoice -notlike "Y*" -and $_remoteChoice -notlike "N*") #Verifies a valid choice has been made

        if($_remoteChoice -like "Y*") #Checks if the user chose to remote into any devices
        {   
            do{ 
                $_specificDevice = Read-Host -Prompt "Would you like to remote into specific devices? (Y/N, if no the program connects sequentially)" #Asks if the user cares which devices get connected to
            }while($_specificDevice -notlike "y*" -and $_specificDevice -notlike "n*") #Verifies a valid choice has been made

            if($_specificDevice -like "y*") #The user has chosen to connect to specific devices
            {
                if($_userRoute -like "p*") #Checks if the user was using prefixes
                {            
                    echo "Which devices would you like to connect to? For example, INFO-TECH-WXXX will be filled in, just provide the suffix 'XXX'" #Asks the user which devices to connect to
                    echo `n
        
                    #Runs through a loop until the user exits or picks too many clients
                    do{
                        do{
                            $_userPrefDevices = Read-Host -Prompt "Device suffix, or 'exit' to stop selecting"

                            if($_userPrefDevices.Length -gt 3) #Checks if the user entered an invalid value
                            {
                                echo "You've entered too many characters, please try again."
                            }
                        }while($_userPrefDevices.Length -gt 3)#Validates the user hasn't entered too many characters    
                            
                        if($_userPrefDevices -notlike "ex*") #Checks the user hasn't selected to exit
                        {
                            $_userPrefDevices = "$_prefix" + "-W" + $_userPrefDevices       
                                 
                            if($_onlineAvailableDevices -contains $_userPrefDevices) #Checks to make sure the device chosen exists. If not, ask to try again and don't store in array 
                            {
                                $_userPrefDevices | Add-Content C:\Temp\GetClients\UserPrefClients.txt #adds the chosen client to the text file
                                $_userPrefDevicesList = Get-Content C:\Temp\GetClients\UserPrefClients.txt #sets the array to the values in the list
                                echo "$_userPrefDevices added to list."
                            }
                            else #Triggers if the device name entered is not in the list
                            {
                                echo "The selected device was not found in the list or is not available, please try again or 'exit'"
                            }
                       }            
                    }while($_userPrefDevices -notlike "ex*" -and $_userPrefDevicesList.Count -lt $_onlineAvailableDevices.Count) #Checks if the user has exited or selected too many clients
                                    
                    if($_userPrefDevices -like "ex*")#Checks if the user chose to exit
                    {
                        if($_userPrefDevicesList.Count -gt 0) #Checks if the user chose any devices
                        {
                            echo `n
                            echo "Beginning connections..."
                        
                            Foreach($_device in $_userPrefDevicesList) #Connects to each online available device
                            {
                                Start-sleep -s 3 #Adds a 3 second delay
                                mstsc /v:$_device #Starts an rdp session with the device in question
                            }
                        }
                    }
                }
                elseif($_userRoute -like "l*") #Checks if the user used a list
                {            
                    echo "Which devices would you like to connect to?" #Asks the user which devices to connect to
                    echo `n   
                 
                    #Runs through a loop until the user exits or picks too many clients
                    do{
                        $_userPrefDevices = Read-Host -Prompt "Device name, or 'exit' to stop selecting"                
                        if($_userPrefDevices -notlike "ex*") #Checks the user hasn't selected to exit
                        {                     
                            if($_onlineAvailableDevices -contains $_userPrefDevices) #Checks to make sure the device chosen exists. If not, ask to try again and don't store in array
                            {
                                $_userPrefDevices | Add-Content C:\Temp\GetClients\UserPrefClients.txt #adds the chosen client to the text file
                                $_userPrefDevicesList = Get-Content C:\Temp\GetClients\UserPrefClients.txt #sets the array to the values in the list
                                echo "$_userPrefDevices added to list."
                            }
                            else #Triggers if the device name entered is not in the list
                            {
                                echo "The selected device was not found in the list or is not available, please try again or 'exit' to stop selecting"
                            }
                       }            
                    }while($_userPrefDevices -notlike "ex*" -and $_userPrefDevicesList.Count -lt $_onlineAvailableDevices.Count) #Checks if the user has exited or selected too many clients

                    if($_userPrefDevices -like "ex*")#Checks if the user chose to exit
                    {
                        if($_userPrefDevicesList.Count -gt 0) #Checks if the user chose any devices
                        {
                            echo `n
                            echo "Beginning connections..."
                        
                            Foreach($_device in $_userPrefDevicesList) #Connects to each online available device
                            {
                                Start-sleep -s 3 #Adds a 3 second delay
                                mstsc /v:$_device #Starts an rdp session with the device in question
                            }
                        }
                    }
                }
                if($_userPrefDevices -like "e*" -and $_userPrefDevicesList -eq $null) #Checks if the user exited without providing input
                {
                    do{
                        $_preExit = Read-Host -Prompt "You exited without selecting any devices, would you like to connect sequentially instead? (Y/N)"
                    }while($_preExit -notlike "y*" -and $_preExit -notlike "n*") #Verifies a valid choice has been made

                    if($_preExit -like "y*") #Checks if the user wants to connect sequentially
                    {
                        do{
                            Try{
                                [Int32]$_remoteAmount = Read-Host -Prompt "How many devices would you like to connect to?" #Asks how many devices the user would like to remote into
                                $_attempt = "success" #If the user enters an integer, the try sets a success
                            } Catch {$_attempt = "fail"} #If the value entered is not an integer, the catch sets a fail
                        }while($_attempt -like "f*") #Checks if the catch has been triggered, or lets the user continue
        
                        if($_remoteAmount -le $_onlineAvailableDevices.Count -and $_remoteAmount -gt 0) #Checks if the user has specified a valid amount not greater than the amount of available devices and greater than 0
                        {
                            echo `n
                            echo "Beginning connections..."

                            $_rdpCount = 0 #Sets the count for the loop to 0
                            Foreach($_onlineAvailableDevice in $_onlineAvailableDevices) #Loops through the list until it hits the specified number
                            {
                                if($_rdpCount -ge $_remoteAmount) #exits the loop if the script tries to connect to the specified amount
                                {
                                    break
                                }                

                                Start-sleep -s 3 #Adds a 3 second delay before beginning to connect
                                mstsc /v:$_onlineAvailableDevice #Starts an rdp session with the device in question
                                $_rdpCount++ #increments the counter
                            }
                        }        
                        elseif($_remoteAmount -gt $_onlineAvailableDevices.Count) #Checks if user choice is more than the available clients and sets it to "all" if so
                        {
                            $_remoteAmount = $_onlineAvailableDevices.Count
                            Write-Host -NoNewline "You chose more than the "$_onlineAvailableDevices.Count" available devices. The program will try and connect to each client."
                            
                            echo `n
                            echo "Beginning connections..."

                            Foreach($_onlineAvailableDevice in $_onlineAvailableDevices) #Connects to each online available device
                            {
                                Start-sleep -s 3 #Adds a 3 second delay before beginning to connect
                                mstsc /v:$_onlineAvailableDevice #Starts an rdp session with the device in question
                            }
                        }
                        else #Triggers if the user has chosen not to connect to any devices
                        {
                            echo "You've chosen not to connect to anything."

                            do{
                                $_repeatChoice = Read-Host -Prompt "Would you like to start over? (y/n)"
                            }while($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks for a valid response
                        }    
                    }
                    else #Triggers if the user has chosen not to connect to any devices
                    {
                        echo "You've chosen not to connect to anything."

                        do{
                            $_repeatChoice = Read-Host -Prompt "Would you like to start over? (y/n)"
                        }while($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks for a valid response
                    }
                }        
            }
            else #The user has chosen not to connect to specific devices, asks for a sequential connection instead
            {
                do{
                    Try{
                        [Int32]$_remoteAmount = Read-Host -Prompt "How many devices would you like to connect to? (0 to exit)" #Asks how many devices the user would like to remote into
                        $_attempt = "success" #If the user enters an integer, the try sets a success
                    } Catch {$_attempt = "fail"} #If the value entered is not an integer, the catch sets a fail
                }while($_attempt -like "f*") #Checks if the catch has been triggered, or lets the user continue
        
                if($_remoteAmount -le $_onlineAvailableDevices.Count -and $_remoteAmount -gt 0) #Checks if the user has specified a valid amount that isn't greater than the amount of available devices, or if they've chosen 0
                {
                    echo `n
                    echo "Beginning connections..."

                    $_rdpCount = 0
                    Foreach($_onlineAvailableDevice in $_onlineAvailableDevices)
                    {
                        if($_rdpCount -ge $_remoteAmount) #exits the loop if the script tries to connect to the specified amount
                        {
                            break
                        }

                        Start-sleep -s 3 #Adds a 3 second delay before beginning to connect
                        mstsc /v:$_onlineAvailableDevice #Starts an rdp session with the device in question
                        $_rdpCount++ #increments the counter
                    }
                }        
                elseif($_remoteAmount -gt $_onlineAvailableDevices.Count) #Checks if user choice is more than the available clients and sets it to "all" if so
                {
                    $_remoteAmount = $_onlineAvailableDevices.Count
                    Write-Host -NoNewline "You chose more than the "$_onlineAvailableDevices.Count" available devices. The program will try and connect to each client."

                    echo `n
                    echo "Beginning connections..."
                        
                    Foreach($_onlineAvailableDevice in $_onlineAvailableDevices) #Connects to each online available device
                    {
                        Start-sleep -s 3 #Adds a 3 second delay
                        mstsc /v:$_onlineAvailableDevice #Starts an rdp session with the device in question
                    }
                }
                else #Triggers if the user has chosen not to connect to any devices
                {
                    echo "You've chosen not to connect to anything."

                    do{
                        $_repeatChoice = Read-Host -Prompt "Would you like to start over? (y/n)"
                    }while($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks for a valid response
                }
            }
        }
        else #Triggers if the user chose not to remote in to any devices
        {
            do{
                $_repeatChoice = Read-Host -Prompt "Would you like to start over? (y/n)"
            }while($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks for a valid response
        }
    }

    if($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks if the user has made a choice regarding restart
    {
        do{
            $_repeatChoice = Read-Host -Prompt "Would you like to start over? (y/n)"
        }while($_repeatChoice -notlike "y*" -and $_repeatChoice -notlike "n*") #Checks for a valid response
    }
}while($_repeatChoice -like "y*") #Reruns the script if the user chooses to

Write-Ascii -InputObject Goodbye! -ForegroundColor Green #Says goodbye to the user

Start-Sleep -s 3 #3 second delay before deleting files and closing

Remove-Item -Path C:\Temp\GetClients -Force -Recurse #Deletes all script created files/folders

cls

Pop-Location
