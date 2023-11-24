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

                                                            Set-Dell1stBootdevice -Bootdevice "NIC" -Password "tintpyal4" -Verbose #Sets the boot order to boot from the NIC
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

    #Offers to let the user restart the online computers
    $_restartChoice = Read-Host -Prompt "`nWould you like to restart the computers that were reachable? There will be no warning before restart. (y/n)"

    #Confirms the user chose to restart
    if($_restartChoice -like "*y*"){
        
        #Offers to restart with a delay
        $_delayChoice = Read-Host -Prompt "`nWould you like to restart the computers with a delay between them? The first will restart immediately, followed by your chosen delay before the next one. (y/n)"

        $_counterB = 0

        $_percentCompleteB = ($_counterB / $_onlineList.Count) * 100
        
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
                        $_delayTimeConfirm = Read-Host -Prompt "You've chosen a delay of $_delayTime. Is this right?"
                    }

                }while($_delayTimeConfirm -notlike "*y*") #Confirms the user is happy with their time choice

                #Waits for the user to start the reboots
                Read-Host -Prompt "`nHit 'Enter' to begin restarting"

                #Loops through the devices restarting them with the chosen delay
                foreach($_device in $_onlineList){
                    Write-Progress -Activity "Restarting computers" -Status $_device -PercentComplete $_percentCompleteB

                    Restart-Computer -ComputerName $_device -Force -Verbose

                    Start-Sleep -s $_delayTime

                    $_counterB++
                }
            }
            else{
                #Loops through the devices restarting them with no delay
                foreach($_device in $_onlineList){

                    Write-Progress -Activity "Restarting computers" -Status $_device -PercentComplete $_percentCompleteB

                    Restart-Computer -ComputerName $_device -Force -Verbose

                    $_counterB++
                }
            }

            #Clear progress bar
            Write-Progress -Activity "Restarting computers" -Status "Ready" -Completed
    }
    else{
        #Reminds the user they've made a change
        Write-Host "`nRemember, until they're imaged, the devices will try to PXE on every boot."
    }
}

#Waits for the user to close the script
Read-Host -Prompt "`nPress enter to close the script"

#Clears the screen
cls
