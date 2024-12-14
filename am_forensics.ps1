# AmCache Driver Analysis Script
# This script scans the AmCache registry hive for drivers not marked as part of Windows.
# It extracts driver metadata and provides results in a grid view or exportable format.

# Ensure the script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You must run this script as an Administrator user"
    exit
}

# Generate a unique identifier for temporary storage
$generated_guid = (New-Guid).ToString()
$temp_directory = "C:\$generated_guid"
$original_working_directory = Get-Location

#
# Create a temporary folder
# Allow a user to escape execution cleanly with 'q'.
#
try{
    New-Item -Path $temp_directory -ItemType Directory -Force | Out-Null
    Write-Host "Created temporary directory at ""$temp_directory"""
    Write-Host " =================================================================="
    Write-Host "You may press 'q' at any time to stop the processing and initiate cleanup of artifacts"
    Write-Host " =================================================================="
} catch {
    Write-Error "Failed to create a temporary directory at ""$temp_directory"""
    exit
}

# Create and link shadow copy
try {
    # Deserialization in VSCode does not allow us to debug WMI objects as it is converted to a static format (no Create()).
    #$shadow_class = Get-WmiObject -List Win32_ShadowCopy
    #$shadow_copy = $shadow_class.Create("C:\", "ClientAccessible")
    #$shadow_copy_device = (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow_copy.ShadowID }).DeviceObject + "\"
    #$shadow_copy_obj = (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow_copy.ShadowID })

    # Create the WMI Shadow Copy class object directly
    $shadow_class = New-Object -TypeName System.Management.ManagementClass -ArgumentList "ROOT\cimv2", "Win32_ShadowCopy", $null

    # Create the shadow copy
    $shadow_copy = $shadow_class.Create("C:\", "ClientAccessible")

    # Extract the shadow copy ID from the returned object
    $shadow_copy_id = $shadow_copy.ShadowID

    # Retrieve the full shadow copy object for further operations
    $shadow_copy_obj = New-Object -TypeName System.Management.ManagementObject -ArgumentList "ROOT\cimv2:Win32_ShadowCopy.ID='$shadow_copy_id'"

    # Retrieve the shadow copy device object path directly using WMI query
    $shadow_copy_device = $shadow_copy_obj.Properties["DeviceObject"].Value + "\"

    
    # This works to delete:
    # $result = $shadow_copy_obj.InvokeMethod("Revert", @($true))
    # Write-Host "Reversion was ${result}"
    # $shadow_copy_obj.Delete()
    # Remove-Item -Path $shadow_copy_device
    $shadow_link = "$temp_directory\shadowcopy"
    cmd /c mklink /d "$shadow_link" "$shadow_copy_device"
} catch {
    Write-Error "Failed to create shadow copy or symbolic link: $_"
    exit
}


#
# Try to clear the registry hive, which will fail in any attempt.
# Tried doing this with giving ownership to Admin upon creation, various object deletion methods in Powershell,
# various shell deletion methods, and deletion with a SYSTEM scheduled task.  All failed.
#
function Clear-RegHive {
    cmd /c reg unload "HKLM\${generated_guid}" *>$null
    $cmd_exit_code = $LASTEXITCODE
        
    if ($cmd_exit_code -eq 0) {
        Write-Host "Registry hive HKLM:\${generated_guid} unloaded successfully."
    } else {
        # This is always true (ERROR: Access is denied.).  Can't even delete this value by spawning a scheduled task as SYSTEM after execution. :(
        # Write-Warning "Failed to unload registry hive at HKLM:\${generated_guid}.  Exit code was ${cmd_exit_code}."
        Write-Warning "Registry hive at HKLM\${generated_guid} will be removed after device restart"
    }
}


# 
# Handle process interrupts gracefully.
#
function Clear-Interrupt {
    Write-Host "Performing artifact cleanup"

    Write-Host "Starting garbage collection"
    [gc]::Collect()
    Start-Sleep -Seconds 2

    # Delete the shadow copy
    try {
        # (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow_copy.ShadowID }).Delete()
        # $result = $shadow_copy_obj.InvokeMethod("Revert", @($true))
        # Write-Host "Reverted the shadow copy:  ${result}"
        # Write-Host "Reversion was ${result}"

        $shadow_copy_obj.Delete()
        Remove-Item -Path $shadow_copy_device
        Write-Host "Successfully removed the shadow copy"
    } catch {
        Write-Warning "Failed to delete the shadow copy:  $_"
    }

    [gc]::Collect()
    Start-Sleep -Seconds 2

    # Remove the symbolic link
    try {
        Remove-Item -Path $shadow_link -Recurse -Force
        Write-Host "Shadow symbolic link ""${shadow_link}"" removed successfully"
    } catch {
        Write-Warning "Failed to delete shadow symbolic link ""${shadow_link}"":  $_"
    }

    # Unload the registry hive
    try {
        $key_path = "HKLM:\${generated_guid}"

        $acl = Get-Acl -Path $key_path
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $key_path -AclObject $acl

        try {
            # Open the parent key
            $registry_key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($generated_guid, $true)
            Write-Host "Opened registry key ${registry_key}"
            if ($registry_key) {
                # Recursively delete all subkeys
                $subKeys = $registry_key.GetSubKeyNames()
                foreach ($subKey in $subKeys) {
                    Write-Host "Attempting to delete subkey ${subKey}"
                    $subkey_path = "${key_path}\${subKey}"
                    $acl = Get-Acl -Path $subkey_path
                    $acl.SetAccessRule($rule)
                    Set-Acl -Path $subkey_path -AclObject $acl
                    $registry_key.DeleteSubKeyTree($subKey)
                    Write-Host "Deleted subkey path ${subkey_path}"
                }
        
                # Close the key
                $registry_key.Close()
        
                Clear-RegHive
            } else {
                Write-Warning "Registry hive HKLM:\${generated_guid} does not exist or cannot be accessed."
            }
        } catch {
            Write-Error "Failed to unload registry hive: $_"
        }

        Write-Host "Registry hive ""${generated_guid}"" unloaded successfully"
    } catch {
        Write-Warning "Failed to unload registry hive ""${generated_guid}"":  $_"
    }

    # Delete the temporary folder
    try {
        Write-Host "Trying to remove temporary folder ""$temp_directory"""
        Remove-Item -Path $temp_directory -Recurse -Force
        Write-Host "Temporary folder ""${temp_directory}"" removed successfully"
    } catch {
        Write-Warning "Failed to delete temporary folder ""${temp_directory}"":  $_"
    }

    exit
}


#
# Register an event handler for 'q' interrupt.
#
$global:interrupted = $false
$event_handler = {
    $global:interrupted = $true
    Write-Host "Caught interrupt.  Attempting to clean up."
    Clear-Interrupt
    exit
}


# Register "interrupt" handler
$subscription = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $event_handler

#
# Load and give temporary (read only) access to the AmCache hive.
#
try {
    cmd /c reg load "HKLM\${generated_guid}" "${shadow_link}\Windows\AppCompat\Programs\AmCache.hve"
    $key_path = "HKLM:\${generated_guid}"
    <# try {
        # Change ownership to Administrators (this did not help, nor creating a SYSTEM schtask for later deletion)
        $acl = Get-Acl -Path $keyPath
        $owner = [System.Security.Principal.NTAccount]"Administrators"
        $acl.SetOwner($owner)
        Set-Acl -Path $keyPath -AclObject $acl
    
        # Grant Full Control to Administrators
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "Administrators", "FullControl", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $keyPath -AclObject $acl
    
        Write-Host "Ownership and permissions updated for HKLM:\$generated_guid."
    } catch {
        Write-Error "Failed to update permissions:  $_"
    } #>
} catch {
    Write-Error "Failed to load registry hive:  $_"
    exit
}

# Initialize result storage
$results_array = @()

# Scan the AmCache for driver entries
try {
    $registry_count = (Get-ChildItem "HKLM:\${generated_guid}\Root\InventoryDriverBinary" | Measure-Object).Count
    $registry_progress = 0

    #
    # We iterate through the InventoryDriverBinary keys in the AmCache hive.  We push/set/pop our location to each
    # entry name.  Stores each result in $results_array.
    #
    Push-Location
    foreach ($key in Get-ChildItem "HKLM:\${generated_guid}\Root\InventoryDriverBinary") {
        # Check for interrupt
        if ($global:interrupted) {
            Write-Warning "Process interupt signaled"
            Clear-Interrupt
        }
        if ([System.Console]::KeyAvailable) {
            $key_press = [System.Console]::ReadKey($true)
            if ($key_press.KeyChar -eq 'q') {
                Write-Host "'Q' press detected.  Attempting cleanup."
                Write-Host "Setting location to ${original_working_directory}"
                Set-Location -Path $original_working_directory
                Clear-Interrupt
            }
        }

        Write-Host "Processing ${key}"

        $registry_progress += 1
        Write-Progress -PercentComplete (100 * $registry_progress / $registry_count) -Activity "Scanning AmCache.hve"
        Set-Location -Path ("Registry::" + $key.Name)

        #
        # Skip drivers marked as "inbox", which are shipped with Windows as part of the operating system.
        # We only want to focus on drivers added by the user/installed via third-party software.
        #
        $inbox_drivers = (Get-ItemProperty -Name DriverInBox -Path .).DriverInBox
        if ($inbox_drivers -ne 1) {
            $driver_company = (Get-ItemProperty -Name DriverCompany -Path .).DriverCompany
            $driver_is_kernel_mode = (Get-ItemProperty -Name DriverIsKernelMode -Path .).DriverIsKernelMode
            $driver_last_write_time = (Get-ItemProperty -Name DriverLastWriteTime -Path .).DriverLastWriteTime
            $driver_time_stamp = (Get-ItemProperty -Name DriverTimeStamp -Path .).DriverTimeStamp
            $driver_name = (Get-ItemProperty -Name DriverName -Path .).DriverName
            $driver_path = if ($driver_name -like "*:\*") {
                # If the path is absolute, use it directly
                $driver_name
            } else {
                # If the path is relative, combine it with $env:SystemRoot
                [System.IO.Path]::Combine($env:SystemRoot, $driver_name)
            }
            $driver_signed = (Get-ItemProperty -Name DriverSigned -Path .).DriverSigned
            $driver_type = (Get-ItemProperty -Name DriverType -Path .).DriverType
            # $driver_version = (Get-ItemProperty -Name DriverVersion -Path .).DriverVersion
            $wdf_version = (Get-ItemProperty -Name WdfVersion -Path .).WdfVersion
            $driver_id = (Get-ItemProperty -Name DriverId -Path .).DriverId
            $driver_checksum = (Get-ItemProperty -Name DriverChecksum -Path .).DriverChecksum
            $image_size = (Get-ItemProperty -Name ImageSize -Path .).ImageSize
            $inf = (Get-ItemProperty -Name Inf -Path .).Inf
            $product = (Get-ItemProperty -Name Product -Path .).Product
            $service = (Get-ItemProperty -Name Service -Path .).Service
            $driver_type_string = ""

            # Decode DriverType flags
            if (($driver_type -band 0x0001) -ne 0) {$driver_type_string += "TYPE_PRINTER "}
            if (($driver_type -band 0x0002) -ne 0) {$driver_type_string += "TYPE_KERNEL "}
            if (($driver_type -band 0x0004) -ne 0) {$driver_type_string += "TYPE_USER "}
            if (($driver_type -band 0x0008) -ne 0) {$driver_type_string += "IS_SIGNED "}
            if (($driver_type -band 0x0010) -ne 0) {$driver_type_string += "IS_INBOX "}
            if (($driver_type -band 0x0040) -ne 0) {$driver_type_string += "IS_WINQUAL "}
            if (($driver_type -band 0x0020) -ne 0) {$driver_type_string += "IS_SELF_SIGNED "}
            if (($driver_type -band 0x0080) -ne 0) {$driver_type_string += "IS_CI_SIGNED "}
            if (($driver_type -band 0x0100) -ne 0) {$driver_type_string += "HAS_BOOT_SERVICE "}
            if (($driver_type -band 0x10000) -ne 0) {$driver_type_string += "TYPE_I386 "}
            if (($driver_type -band 0x20000) -ne 0) {$driver_type_string += "TYPE_IA64 "}
            if (($driver_type -band 0x40000) -ne 0) {$driver_type_string += "TYPE_AMD64 "}
            if (($driver_type -band 0x100000) -ne 0) {$driver_type_string += "TYPE_ARM "}
            if (($driver_type -band 0x200000) -ne 0) {$driver_type_string += "TYPE_THUMB "}
            if (($driver_type -band 0x400000) -ne 0) {$driver_type_string += "TYPE_ARMNT "}
            if (($driver_type -band 0x800000) -ne 0) {$driver_type_string += "IS_TIME_STAMPED "}

            # Store data
            $row = [PSCustomObject]@{
                DriverCompany           = $driver_company
                DriverIsKernelMode      = $driver_is_kernel_mode
                DriverLastWriteTime     = $driver_last_write_time
                DriverTimeStamp         = $driver_time_stamp
                DriverName              = $driver_name
                DriverPath              = $driver_path
                Inf                     = $inf
                DriverSize              = $image_size
                DriverSigned            = $driver_signed
                # 32-bit length (DWORD)
                DriverType              = ([Convert]::ToString($driver_type, 2)).PadLeft(32, "0")
                DriverTypeString        = $driver_type_string
                DriverVersion           = $driver_version
                DriverChecksum          = $driver_checksum
                WdfVersion              = $wdf_version
                DriverId                = $driver_id
                Product                 = $product
                Service                 = $service
            }
            $results_array += $row
        }

        # Unregister-Event -SubscriptionId $subscription.Id
    }
    Pop-Location
} catch {
    Write-Error "An error occurred during the AmCache scan:  $_"
}

# Output results
$results_array | Out-GridView -Title "AmCache Driver Analysis"
$results_csv_path = "C:\Windows\Temp\AmCacheDriverAnalysis.csv"
# Overwrite former CSV if necessary
$results_array | Export-Csv -Path "${results_csv_path}" -NoTypeInformation -Force

Write-Host "Results were saved to ${results_csv_path}"

#
# Try to cleanup generated resources
#
try {
    # Trigger garbage collection and allow sleep to let handle to registry unwind.
    Write-Host "Starting garbage collection"
    [gc]::Collect()
    Start-Sleep -Seconds 2

    # result = $shadow_copy_obj.InvokeMethod("Revert", @($true))
    # Write-Host "Reverted the shadow copy:  ${result}"
    # Write-Host "Reversion was ${result}"
    $shadow_copy_obj.Delete()
    Remove-Item -Path $shadow_copy_device

    # This will also fail.
    Clear-RegHive

    Write-Host "Unloaded ${generated_guid}"
    Remove-Item -Path "${shadow_link}" -Recurse -Force
    # THIS SHOULD ERROR
    # (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow_copy.ShadowID }).Delete() | Out-Null

    Remove-Item -Path $temp_directory -Recurse -Force
    
    # Unregister-Event -SubscriptionId $subscription.Id
    <# [System.Console]::CancelKeyPress -= {
        param($sender, $args)

        $args.Cancel = $true
    } #>
    Write-Host "Cleanup finished"
} catch {
    Write-Warning "Cleanup error:  $_"
}

