﻿#Imports Derksens textbox entry gui/online checker
if (-Not (Get-Module SD36.IMS.PowerShell.Utility)){
    Import-Module '\\info-fs1\dev\Scripts\PowerShellModules\SD36.IMS.PowerShell.Utility'
    }

Write-Host "This script will prepare a set of chosen computers to be imaged, by setting their boot order to the 'USB NIC(IPV4)'. It will then allow you to trigger mass reboots with an optional delay."

$_continueChoice = Read-Host -Prompt "`nPlease note: you will still have to hit 'ENTER' on the computers to select the network boot. Would you like to continue? (y/n)"

if($_continueChoice -like "*y*"){

    $_computerList = Get-ComputerListGUI #Gets the list of computers to target
    $_onlineList = @()
    $_offlineList = @()
    $_total = $_computerList.Count
    $_counterA = 0
    $_percentCompleteA = ($_counterA / $_total) * 100

    foreach($_pc in $_computerList){

        Write-Progress -Activity "Preparing for imaging..." -Status $_pc -PercentComplete $_percentCompleteA

        if(Test-Connection -ComputerName $_pc -Count 1 -Quiet){
            
            $_onlineList += $_pc
            
            Invoke-Command -ComputerName $_pc -ScriptBlock { 
                                                            Set-ExecutionPolicy Bypass -Force

                                                            Install-Package -Name Nuget -Force

                                                            Install-Module DellBIOSProvider -Force

                                                            Import-Module DellBIOSProvider -Force

                                                            Set-Dell1stBootdevice -Bootdevice "NIC" -Password "tintpyal4" -Verbose
                                                            }
        }
        else{
            $_offlineList =+ $_pc
        }

        $_counterA++
    }

    if($_offlineList){
        Write-Host "The following devices were unreachable:"
        Write-Host $_offlineList
    }

    Write-Progress -Activity "Preparing for imaging..." -Status "Ready" -Completed

    $_restartChoice = Read-Host -Prompt "`nWould you like to restart the computers that were reachable? There will be no warning before restart. (y/n)"

    if($_restartChoice -like "*y*"){
        
        $_delayChoice = Read-Host -Prompt "`nWould you like to restart the computers with a delay between them? The first will restart immediately, followed by your chosen delay before the next one. (y/n)"
        
            if($_delayChoice -like "*y*"){

                $_delayTime = Read-Host -Prompt "`nEnter your desired delay (in seconds)"

                Read-Host -Prompt "`nHit 'Enter' to begin restarting"

                foreach($_device in $_onlineList){
                    Restart-Computer -ComputerName $_device -Force -Verbose
                    Start-Sleep -s $_delayTime
                }
            }
            else{
                foreach($_device in $_onlineList){
                    Restart-Computer -ComputerName $_device -Force -Verbose
                }
            }
    }
    else{
        Write-Host "`nRemember, until they're imaged, the devices will try to PXE on every boot."
    }
}

Read-Host -Prompt "`nPress enter to close the script"

cls