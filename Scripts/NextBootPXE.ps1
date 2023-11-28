#Imports Derksens textbox entry gui/online checker
if (-Not (Get-Module SD36.IMS.PowerShell.Utility)){
    Import-Module '\\info-fs1\dev\Scripts\PowerShellModules\SD36.IMS.PowerShell.Utility'
    }

#Warning message
Write-Host "This script will prepare a set of chosen computers to be imaged, by setting their boot order to the 'USB NIC(IPV4)'. It will then allow you to trigger mass reboots with an optional delay."

#Confirms the user wants to proceed, or exits the script
$_continueChoice = Read-Host -Prompt "`nPlease note: you will still have to hit 'ENTER' on the computers to select the network boot. Would you like to continue? (y/n)"

#Begins the script
if($_continueChoice -like "*y*"){

    #VARIABLES
    $_computerList = Get-ComputerListGUI #Gets the list of computers to target
    $_onlineList = @() #Holds the reachable computers
    $_offlineList = @() #Holds the unreachable computers
    $_total = $_computerList.Count #Contains the number of computers to be hit
    $_counterA = 0 #Counter for iteration
    
    $_imageType = Read-Host -Prompt "Are you imaging with the USB key method? (y/n)"

    if($_imageType -like "*y*"){
        Write-Host "You'll have to restart the computer(s) with the USB attached. The script won't see it as a boot option otherwise."

        #Add a restart with wait?

        Read-Host -Prompt "Press 'Enter' to continue"
    }

    #Loops through the chosen devices
    foreach($_pc in $_computerList){
        
        #Calculates the number of devices left to work on for the progress bar
        $_percentCompleteA = ($_counterA / $_total) * 100

        #Displays a progress bar
        Write-Progress -Activity "Preparing for imaging..." -Status $_pc -PercentComplete $_percentCompleteA

        #Checks if the device is reachable
        if(Test-Connection -ComputerName $_pc -Count 1 -Quiet){            
            
            #Adds the device to a list of online devices
            $_onlineList += $_pc
            
            #Runs the commands on the targeted computers
            Invoke-Command -ComputerName $_pc -ScriptBlock { 
                                                                Set-ExecutionPolicy Bypass -Force #Enables commands to be run on the device
                                                                                                     
                                                                Install-Package -Name Nuget -Force #Used to install the Dell module

                                                                Install-Module DellBIOSProvider -Force #Installs the Dell module

                                                                Import-Module DellBIOSProvider -Force #Ensures the Dell module gets initialized

                                                                if($_imageType -like "*y*"){
                                                                    Set-Dell1stBootdevice -Bootdevice "UEFI" -Password "tintpyal4" #Sets the boot order to boot from the USB
                                                                }
                                                                else{
                                                                    Set-Dell1stBootdevice -Bootdevice "NIC" -Password "tintpyal4" #Sets the boot order to boot from the NIC
                                                                }
                                                            }
        }
        else{
            #Adds the device to a list of offline devices to ignore
            $_offlineList =+ $_pc
        }
        #Increments the counter
        $_counterA++
    }

    #Checks for offline devices and lists them for convenience
    if($_offlineList){
        Write-Host "The following devices were unreachable:"
        Write-Host $_offlineList
    }
    #Clears the progress bar
    Write-Progress -Activity "Preparing for imaging..." -Status "Ready" -Completed

    #Asks how the user wants to proceed
    $_powerChoice = Read-Host -Prompt "`nWould you like to restart, shutdown, or leave the computers on? (r/s/o)"

        $_counterB = 0
        
        #Runs until the user picks a proper choice
        do{
            switch ($_powerChoice) {

            #The user chose to restart
            "*r*" {

                    $_delayChoice = Read-Host -Prompt "`nWould you like to add a delay between restarts? The first will restart immediately, followed by your chosen delay before the next one. (y/n)"
                    
                    #Confirms they chose a delay
                    if($_delayChoice -like "*y*"){
                        do{
                            #Asks the user for a desired delay
                            $_delayTime = Read-Host -Prompt "`nEnter your desired delay (in seconds)"

                            #If the time chosen is one minute or more
                            if($_delayTime -ge 60){
                                $_convertedDelay = [timespan]::FromSeconds($_delayTime) #Converts seconds to minutes
                                $_convertedDelay2 = ("{0:mm\:ss}" -f $_convertedDelay) #Formats the output to MM:SS
                            }
                            else{
                                $_convertedDelay = $_delayTime
                            }

                            #Checks if the user picked more than 0 seconds
                            if($_delayTime -gt 0){
                                $_delayTimeConfirm = Read-Host -Prompt "You've chosen a delay of $_convertedDelay2. Is this right?"
                            }
                            else{
                                $_delayTimeConfirm = Read-Host -Prompt "You've chosen a delay of $_delayTime seconds. Is this right?"
                            }

                        }while($_delayTimeConfirm -notlike "*y*") #Confirms the user is happy with their time choice

                        #Waits for the user to start the reboots
                        Read-Host -Prompt "`nHit 'Enter' to begin restarting"

                        #Loops through the devices restarting them with the chosen delay
                        foreach($_device in $_onlineList){
                            $_percentCompleteB = ($_counterB / $_onlineList.Count) * 100
                        
                            Write-Progress -Activity "Restarting computers" -Status $_device -PercentComplete $_percentCompleteB

                            Restart-Computer -ComputerName $_device -Force -Verbose

                            Start-Sleep -s $_delayTime

                            $_counterB++
                        }
                    }
                    else{
                        #Waits for the user to start the reboots
                        Read-Host -Prompt "`nHit 'Enter' to begin restarting"

                        #Loops through the devices restarting them with no delay
                        foreach($_device in $_onlineList){

                            Write-Progress -Activity "Restarting computers..." -Status $_device -PercentComplete $_percentCompleteB

                            Restart-Computer -ComputerName $_device -Force -Verbose

                            $_counterB++
                        }
                    }
                    
                    #Clear progress bar
                    Write-Progress -Activity "Restarting computers..." -Status "Ready" -Completed
                }

                "*s*" {
                        #Waits for the user to start the reboots
                        Read-Host -Prompt "`nHit 'Enter' to begin shutting down"

                        #Loops through the devices restarting them with the chosen delay
                        foreach($_device in $_onlineList){
                            $_percentCompleteB = ($_counterB / $_onlineList.Count) * 100
                        
                            Write-Progress -Activity "Shutting down computers" -Status $_device -PercentComplete $_percentCompleteB

                            #Shuts down the reachable computers
                            Stop-Computer -ComputerName $_device -Force -Verbose

                            $_counterB++
                        }

                        #Clear progress bar
                        Write-Progress -Activity "Shutting down computers" -Status "Ready" -Completed
                }

                "*o*" {
                        #Checks if the user wants to revert the changes
                        $_revertChoice = Read-Host -Prompt "`nSince you aren't restarting, did you want to revert the changes? (y/n)"

                        #Confirms the user wants to revert the changes
                        if($_revertChoice -like "*y*"){
                            #Loops through the online computers
                            foreach($_item in $_onlineList){
                                $_percentCompleteB = ($_counterB / $_onlineList.Count) * 100
                                
                                Write-Progress -Activity "Reverting computers..." -Status $_device -PercentComplete $_percentCompleteB

                                #Sets the reachable computers to boot from the hard drive as normal
                                Invoke-command -ComputerName $_item -ScriptBlock {Set-Dell1stBootdevice -Bootdevice "Windows Boot Manager" -Password "tintpyal4"} #Sets the boot order to boot from the hard drive
                                Write-Host "$_item reverted to normal boot" -ForegroundColor Green
                            }
                            #Clear progress bar
                            Write-Progress -Activity "Shutting down computers" -Status "Ready" -Completed
                        }
                        else{
                            #Reminds the user they've made a change
                            Write-Host "`nRemember, until they're imaged, the devices will try to PXE on every boot."
                        }
                }

                }
            } while ($_powerChoice -notlike "*r*" -and $_powerChoice -notlike "*s*" -and $_powerChoice -notlike "*o*")
}

#Waits for the user to close the script
Read-Host -Prompt "`nPress enter to close the script"

#Clears the screen
cls
