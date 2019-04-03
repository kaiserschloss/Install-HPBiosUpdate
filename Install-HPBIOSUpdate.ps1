<#
.Synopsis
   Write-Log writes a message to a specified log file with the current time stamp.
.DESCRIPTION
   The Write-Log function is designed to add logging capability to other scripts.
   In addition to writing output and/or verbose you can write to a log file for
   later debugging.
.NOTES
   Created by: Jason Wasser @wasserja
   Modified: 11/24/2015 09:30:19 AM  

   Changelog:
    * Code simplification and clarification - thanks to @juneb_get_help
    * Added documentation.
    * Renamed LogPath parameter to Path to keep it standard - thanks to @JeffHicks
    * Revised the Force switch to work as it should - thanks to @JeffHicks

   To Do:
    * Add error handling if trying to create a log file in a inaccessible location.
    * Add ability to write $Message to $Verbose or $Error pipelines to eliminate
      duplicates.
.PARAMETER Message
   Message is the content that you wish to add to the log file. 
.PARAMETER Path
   The path to the log file to which you would like to write. By default the function will 
   create the path and file if it does not exist. 
.PARAMETER Level
   Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
.PARAMETER NoClobber
   Use NoClobber if you do not wish to overwrite an existing file.
.EXAMPLE
   Write-Log -Message 'Log message' 
   Writes the message to c:\Logs\PowerShellLog.log.
.EXAMPLE
   Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
   Writes the content to the specified log file and creates the path and file specified. 
.EXAMPLE
   Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
   Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
.LINK
   https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
#>
function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path='C:\Windows\Logs\PowerShellLog.log',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

$LogPath = "C:\Windows\Logs\Software"
$LogFile = "BiosUpdate.log"
$Log = "$LogPath\$LogFile"

try
{
    $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
}
catch
{
   Write-Log -Message "Unable to create COM Object Microsoft.SMS.TSEnvironment.  Likely not running in a task sequence." -Path $Log
}

If($tsenv)
{
    $IsInTS = $true
}
else
{
    $IsInTS = $false
}

Write-Log -Message "Beginning BIOS Update" -Path $Log

$Manufacturer = (Get-WMIObject -Class Win32_ComputerSystem).Manufacturer

If($Manufacturer -eq "HP" -or $Manufacturer -eq "Hewlett-Packard")
{
    Write-Log -Message "Checking for HP BIOS update" -Path $Log
    If(Test-Path "$PSScriptRoot\Modules\HPClientManagement.psm1")
    {
      Import-Module "$PSScriptRoot\Modules\HPClientManagement.psm1"
    }
    else
    {
      Write-Log "HP Client Management Module $PSScriptRoot\Modules\HPClientManagement.psm1 not found. Exiting." -Path $Log
      Exit 1
    }
    
    $IsBiosUpdateAvailable = Get-HPBiosUpdates -check
    If($IsBiosUpdateAvailable -eq "True")
    {
        Write-Log -Message "The BIOS is up to date" -Path $Log
        If($IsInTS)
        {
            $tsenv.Value("UpdateBiosAtRestart") = "FALSE"
        }
        
    }
    elseif($IsBiosUpdateAvailable = "False")
    {
        If(Test-Path "$PSScriptRoot\Modules\HPSoftpaq.psm1")
        {
          Import-Module "$PSScriptRoot\Modules\HPSoftpaq.psm1"
        }
        else
        {
          Write-Log "HP Softpaq Module $PSScriptRoot\Modules\HPsoftpaq.psm1 not found. Exiting." -Path $Log
          Exit 1
        }
        
        $BiosUpdateId = $null
        $BiosUpdateName = $null

        Try
        {
            [string]$ProductID = $(Get-HPDeviceProductID).ToLower()
            $BiosUpdates = Get-SoftpaqList -platform $ProductID -category bios -Verbose -overwrite | Where-Object { $_.Name -notmatch "Utilities" }
            ForEach($BiosUpdate in $BiosUpdates)
            {
                If($BiosUpdate.Id)
                {
                    $BiosUpdateId = $BiosUpdate.Id
                    $BiosUpdateName = $BiosUpdate.Name
                    Write-Log -Message "Found BIOS update $BiosUpdateId - $BiosUpdateName" -Path $Log
                }
            }
        }
        catch
        {
            Write-Log "Unable to get a list of Softpaqs for this system. Exiting." -Path $Log
            Exit 2
        }

        If($BiosUpdateId)
        {
            Write-Log -Message "Checking if the operating system drive is encrypted" -Path $Log
            [version]$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
            If($OSVersion.Major -eq 10)
            {
                $EncryptionStatus = get-bitlockervolume | Where-Object { $_.MountPoint -eq $env:SystemDrive }
                Write-Log -Message "Encryption status of $env:SystemDrive is $($EncryptionStatus.VolumeStatus)" -Path $Log
                If($EncryptionStatus.VolumeStatus -eq "FullyEncrypted")
                {
                    Write-Log -Message "Protection status of $env:SystemDrive is $($EncryptionStatus.ProtectionStatus)" -Path $Log
                    If($EncryptionStatus.ProtectionStatus -eq "On")
                    {
                        Write-Log -Message "Suspending BitLocker" -Path $Log
                        Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 | Out-Null
                    }
                    else
                    {
                        Write-Log -Message "Protectors are not enabled on the operating system drive" -Path $Log
                    }
                }
                else
                {
                    Write-Log -Message "The operating system drive is not encrypted" -Path $Log
                }
            }
            ElseIf($OSVersion.Major -eq 6)
            {
                $EncryptionStatus = (Get-WmiObject -Class Win32_encryptablevolume -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption" -Filter "DriveLetter = '$env:SystemDrive'").ProtectionStatus
                If($EncryptionStatus -eq 1)
                {
                    Write-Log -Message "Suspending BitLocker" -Path $Log
                    Start-Process -FilePath "manage-bde.exe" -ArgumentList "-protectors -disable $env:SystemDrive"
                }
                else
                {
                    Write-Log -Message "Protectors are not enabled on the operating system drive" -Path $Log
                }
            }
            Else
            {
                 Write-Log -Message "Unknown operating system version $($OSVersion.Major) detected." -Path $Log
                 Write-Log -Message "Attempting to suspend BitLocker" -Path $Log
                 Start-Process -FilePath "manage-bde.exe" -ArgumentList "-protectors -disable $env:SystemDrive"
            }

            
            Write-Log -Message "BIOS update for system is $($BiosUpdateId) - $($BiosUpdateName)" -Path $Log
            
            Try
            {
              Set-HPBiosSettingValue -Name "Audio Alerts During Boot" -Value "Disable" -password $password
              Write-Log -Message "Set BIOS setting Audio Alerts During Boot to Disable" -Path $Log
            }
            catch
            {
              Write-Log -Message "Unable to set BIOS setting Audio Alerts During Boot to Disable" -Path $Log
            }
            Write-Log -Message "Downloading and installing update" -Path $Log
            Try
            {
                Get-Softpaq -number ($BiosUpdateId).Replace("sp","") -action silentinstall -overwrite
                Write-Log -Message "BIOS update will complete at next restart." -Path $Log
            }
            catch
            {
                Write-Log -Message "There was a problem downloading $BiosUpdateId." -Path $Log
                Exit 3
            }

            If($IsInTS)
            {
                $tsenv.Value("UpdateBiosAtRestart") = "TRUE"
            }
        }
        else
        {
            Write-Log -Message "There is no System BIOS softpaq available for this system." -Path $Log
            If($IsInTS)
            {
                $tsenv.Value("UpdateBiosAtRestart") = "FALSE"
            }
        }
    }
    else
    {
        Write-Log -Message "No BIOS update was found for this system" -Path $Log
        If($IsInTS)
        {
            $tsenv.Value("UpdateBiosAtRestart") = "FALSE"
        }
    }
}

Write-Log -Message "BIOS Update script complete." -Path $Log