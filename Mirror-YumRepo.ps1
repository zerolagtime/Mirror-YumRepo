﻿<#
.SYNOPSIS 

    Mirror a YUM repository without having a Linux machine, even host the mirror on IIS. 

.DESCRIPTION

    Some corporate networks are extremely reluctant to give end-point control to arbitrary
    users.  If your job is to patch Linux machines that are disconnected from the Internet,
    it can be just a little difficult to get updates as they appear in a YUM repository
    and copied into your disconnected lab. 
      
    This program will connect to the repository, pull down the catalog, and compare the local
    files with the remote files.  New files are pulled down.  If the DeltaZip command line
    parameter is provided, then a ZIP file is created with the catalog and all new RPMs,
    including SRPM and Delta RPMS.  That ZIP file can just be laid on top of an existing
    repository on the disconnected network and hosted by any web server.  Be sure that
    any web server setup has a default MIME type that tags files as application/octet-stream.
    The DaysBack command line option, when paired with the DeltaZip, will put a copy of 
    all downloads created in the last few days into the ZIP, even if they are already cached
    locally.  

    Note that files which have been removed from the remote repository may be deleted from the
    local cache, they will not be deleted from any offline systems. 

.Parameter MirrorRoot

    The URI of a network-accessible repository of multiple branches of repositories.

.Parameter Repository

    The relative path after the -MirrorRoot parameter used to identify which specific repository
    to mirror.  The local file path structure will mirror this parameter.

.Parameter DeltaZip

    The name of a compressed folder used to store an update to the catalog and any new
    files since the last run of this program.  The resulting ZIP file can be overlaid
    onto an existing tree structure on a disconnected system.  See -TrimCache
    for a technique on removing local files that are no longer on the mirror site.

    This parameter also accepts date and time parameters inside the provided file name.
    The Unix Time escape characters are braced before and after with hashtag signs.
    See the examples for potential defaults.  These automatic substitutions allow for
    a great -SavePreferences setting.

.Parameter DaysBack

    After updating the catalog from the mirror site, add all files found that are
    newer than the specified number of days to the ZIP file specified with -DeltaZip.
    The -DeltaZip option must be specified.  This is good for "catching up" a secondary
    offline system that may have missed an update CD.

.Parameter VerifyAllChecksums

    Using the local database, compute the checksum of all locally cached files.
    Any files which fail are deleted from the local disk.
    Pair with -TrimCache to clean up the local disk at the same time.

.Parameter TrimCache

    Using the local database, identify files on disk that are no longer in the catalog
    and delete them.  Good for offline networks to clean up RPMs no longer being hosted 
    on the main site.

.Parameter TrimCache

    Save the MirrorDir, Repo, and DeltaZip settings to a preferences file in your %APPDIR%
    folder.  The next time you call the script, those settings will override the defaults in
    this application, which makes it nice to call quickly on a daily or weekly basis without
    having to retype the same parameters every day.  Also nice if your sysadmin doesn't let 
    you run .bat or .cmd files.

.Parameter ClearPreferences

    Take the settings saved with -SavePreferences and erase them, going back to the script 
    defaults.  Call this parameter if you are debugging a problem and want to see if the 
    preferences are getting in the way.

.Parameter Verbose

    This common parameter shows more about what is going on during
    the evaluate and download process

.Parameter Debug

    This common parameter shows each individual step of the process.

.LINK

    https://github.com/zerolagtime/Powershell
       
.Notes 
    Author		: Charlie Todd <zerolagtime@gmail.com>
    Version		: 1.0 - 2016/03/28 - Initial release - no Internet access
    Copyright   : Copyright 2016 Charlie Todd
                  Licensed under the Apache License, Version 2.0 (the "License");
    Permissions : Local execution policies may prohibit you from
                  running this program.  In that case, open a 
                  PowerShell window and type:
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
                  Additionally, this script can be called from a shortcut with
                  the destination set to
                    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass some_folder\Mirror-DisaMcafee.ps1
    Credit      : GZIP compress and decompress - Copyright 2013 Robert Nees - Apache License 2.0
                : Jeffery Hicks at mcpmag.com for his PowerShell File Frontier article on ZIP files
#>
[CmdletBinding()]
Param(
    [parameter()][string]$MirrorRoot,
    [parameter()][string]$Repository,
    [parameter()][string]$DeltaZip,
    [parameter()][int]$DaysBack,
    [parameter()][switch]$VerifyAllChecksums,
    [parameter()][switch]$TrimCache,
    [parameter()][switch]$SavePreferences,
    [parameter()][switch]$ClearPreferences
)
Set-StrictMode –Version latest
#Requires -Version 4

$Defaults = @{
    MirrorRoot="http://mirror.cisp.com/CentOS/7"
    Repository="cloud/x86_64/openstack-liberty"
    DeltaZip=""
}
$PreferencesFile = Join-Path ([System.Environment]::GetFolderPath(`
                              [System.Environment+SpecialFolder]::ApplicationData)) `
                            "yumrepo.json"

$repomd="repodata/repomd.xml"
$mirrorFolder=(Get-Location)

$URIsToGet = New-Object System.Collections.Queue
$FilesToExpand = New-Object System.Collections.Queue

# --------------------------------------------------------------------------------------------
<#
.NOTES
    Copyright 2013 Robert Nees
    Licensed under the Apache License, Version 2.0 (the "License");
.SYNOPSIS
    GZip Compress and DeCompress
.DESCRIPTION
    A 8k buffered GZip (.gz) Compress and DeCompress functions that support pipelined input
.LINK
    http://sushihangover.blogspot.com
.LINK
    https://github.com/sushihangover
#>
function Compress-GZip {
    <#
    .NOTES
        Copyright 2013 Robert Nees
        Licensed under the Apache License, Version 2.0 (the "License");
    .SYNOPSIS
        GZip Compress (.gz)
    .DESCRIPTION
        A buffered GZip (.gz) Compress function that support pipelined input
    .Example
        ls .\NotCompressFile.xml | Compress-GZip -Verbose -WhatIf
    .Example
        Compress-GZip -FullName NotCompressFile.xml -NewName Compressed.xml.funkyextension
    .LINK
        http://sushihangover.blogspot.com
    .LINK
        https://github.com/sushihangover
    #>
    [cmdletbinding(SupportsShouldProcess=$True,ConfirmImpact="Low")]
    param (
        [Alias("PSPath")][parameter(mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][string]$FullName,
        [Alias("NewName")][parameter(mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)][string]$GZipPath,
        [parameter(mandatory=$false)][switch]$Force
    )
    Process {
        $_BufferSize = 1024 * 8
        if (Test-Path -Path $FullName -PathType Leaf) {
            Write-Verbose "Reading from: $FullName"
            if ($GZipPath.Length -eq 0) {
                $tmpPath = ls -Path $FullName
                $GZipPath = Join-Path -Path ($tmpPath.DirectoryName) -ChildPath ($tmpPath.Name + '.gz')
            }
            if (Test-Path -Path $GZipPath -PathType Leaf -IsValid) {
                Write-Verbose "Compressing to: $GZipPath"
            } else {
                Write-Error -Message "$FullName is not a valid path/file"
                return
            }
        } else {
            Write-Error -Message "$GZipPath does not exist"
            return
        }
        if (Test-Path -Path $GZipPath -PathType Leaf) {
            If ($Force.IsPresent) {
                if ($pscmdlet.ShouldProcess("Overwrite Existing File @ $GZipPath")) {
                    Touch-File $GZipPath
                }
            }
        } else {
            if ($pscmdlet.ShouldProcess("Create new Compressed File @ $GZipPath")) {
                Touch-File $GZipPath
            }
        }
        if ($pscmdlet.ShouldProcess("Creating Compress File @ $GZipPath")) {
            Write-Verbose "Opening streams and file to save compressed version to..."
            $input = New-Object System.IO.FileStream (ls -path $FullName).FullName, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read);
            $output = New-Object System.IO.FileStream (ls -path $GZipPath).FullName, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
            $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
            try {
                $buffer = New-Object byte[]($_BufferSize);
                while ($true) {
                    $read = $input.Read($buffer, 0, ($_BufferSize))
                    if ($read -le 0) {
                        break;
                    }
                    $gzipStream.Write($buffer, 0, $read)
                }
            }
            finally {
                Write-Verbose "Closing streams and newly compressed file"
                $gzipStream.Close();
                $output.Close();
                $input.Close();
            }
        }
    }
}
function Expand-GZip {
    <#
    .NOTES
        Copyright 2013 Robert Nees
        Licensed under the Apache License, Version 2.0 (the "License");
    .SYNOPSIS
        GZip Decompress (.gz)
    .DESCRIPTION
        A buffered GZip (.gz) Decompress function that support pipelined input
    .Example
        ls .\RegionName.cs.gz | Expand-GZip -Verbose -WhatIf
    .Example
        Expand-GZip -FullName CompressFile.xml.gz -NewName NotCompressed.xml
    .LINK
        http://sushihangover.blogspot.com
    .LINK
        https://github.com/sushihangover
    #>
    [cmdletbinding(SupportsShouldProcess=$True,ConfirmImpact="Low")]
    param (
        [Alias("PSPath")][parameter(mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][string]$FullName,
        [Alias("NewName")][parameter(mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)][string]$GZipPath = $null,
        [parameter(mandatory=$false)][switch]$Force
    )
    Process {
        if (Test-Path -Path $FullName -PathType Leaf) {
            Write-Verbose "Reading from: $FullName"
            if ($GZipPath.Length -eq 0) {
                $tmpPath = ls -Path $FullName
                $GZipPath = Join-Path -Path ($tmpPath.DirectoryName) -ChildPath ($tmpPath.BaseName)
            }
            if (Test-Path -Path $GZipPath -PathType Leaf -IsValid) {
                Write-Verbose "Decompressing to: $GZipPath"
            } else {
                Write-Error -Message "$GZipPath is not a valid path/file"
                return
            }
        } else {
            Write-Error -Message "$FullName does not exist"
            return
        }
        if (Test-Path -Path $GZipPath -PathType Leaf) {
            If ($Force.IsPresent) {
                if ($pscmdlet.ShouldProcess("Overwrite Existing File @ $GZipPath")) {
                    Touch-File $GZipPath
                }
            }
        } else {
            if ($pscmdlet.ShouldProcess("Create new decompressed File @ $GZipPath")) {
                Touch-File $GZipPath
            }
        }
        if ($pscmdlet.ShouldProcess("Creating Decompressed File @ $GZipPath")) {
            Write-Verbose "Opening streams and file to save compressed version to..."
            $input = New-Object System.IO.FileStream (ls -path $FullName).FullName, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read);
            $output = New-Object System.IO.FileStream (ls -path $GZipPath).FullName, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
            $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
            try {
                $buffer = New-Object byte[](1024);
                while ($true) {
                    $read = $gzipStream.Read($buffer, 0, 1024)
                    if ($read -le 0) {
                        break;
                    }
                    $output.Write($buffer, 0, $read)
                }
            }
            finally {
                Write-Verbose "Closing streams and newly decompressed file"
                $gzipStream.Close();
                $output.Close();
                $input.Close();
            }
        }
    }
}
# --------------------------------------------------------------------------------------------
function Initialize-File{
    <#
        .NOTES
            Copyright 2013 Robert Nees
            Licensed under the Apache License, Version 2.0 (the "License");
            http://sushihangover.blogspot.com
        .SYNOPSIS
            touch-file -- change file access and modification times
        .DESCRIPTION
         The touch utility sets the modification and access times of files.  If any file does not exist, 
         it is created with default permissions. (see examples)
     
            -a (AccessTime) Change just the access time of the file.
            -c (Create) Do not create the file if it does not exist.  The touch utility does not treat 
                this as an error.  No error messages are displayed and the exit value is not affected.
            -f (Force) Attempt to force the update, even if the file permissions do not currently permit 
                it. FYI: Only valid on file creation!
            -m (ModificationTime) Change just the modification time of the file.
            -n (CreationTime) Change just the creation time of the file (when it was 'n'ew).
            -r (Replace) Use the access and modifications times from the specified file instead of the 
                current time of day.
            -t (Time) Change the access and modification times to the specified time instead of the 
                current time of day.  The argument is of the form of a .Net DateTime string
        .EXAMPLE
            TODO : Add Examples
        .LINK
            http://sushihangover.blogspot.com
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True)][String]$FileName,
        [Parameter(Mandatory=$false)][Alias('r')][String]$Replace = "",
        [Parameter(Mandatory=$false)][Alias('t')][String]$Time = "",
        [Parameter(Mandatory=$false)][Alias('c')][Switch]$Create,
        [Parameter(Mandatory=$false)][Alias('a')][Switch]$AccessTime,
        [Parameter(Mandatory=$false)][Alias('m')][Switch]$ModificationTime,
        [Parameter(Mandatory=$false)][Alias('n')][Switch]$CreationTime,
        [Parameter(Mandatory=$false)][Alias('f')][Switch]$Force
    )
    begin {
        function Update-FileSystemInfo([System.IO.FileSystemInfo]$fsInfo) {
            if ($Time -ne $null) {
                $fsInfo.CreationTime = $CurrentDateTime
                $fsInfo.LastWriteTime = $CurrentDateTime
                $fsInfo.LastAccessTime = $CurrentDateTime
            } else {
                if ($AccessTime.IsPresent) {
                    $fsInfo.LastAccessTime = $CurrentDateTime
                }
                if ($ModificationTime.IsPresent) {
                    $fsInfo.LastWriteTime = $CurrentDateTime
                }
                if ($CreationTime.IsPresent) {
                    $fsInfo.CreationTime = $CurrentDateTime
                }
            }
        }
   
        function Touch-NewFile {
            [cmdletbinding(SupportsShouldProcess=$True)]
            Param(
                [Parameter(Mandatory=$True)][String]$FileName
            )
            if ($Force.IsPresent ) {
                Set-Content -Path ($FileName) -Value ($null) -Force
            } else {
                Set-Content -Path ($FileName) -Value ($null)
            }
            $fsInfo = new-object System.IO.FileInfo($FileName)
            return $fsInfo
        }

        if ($Replace -ne "") {
            try {
                $replaceInfo = Get-ChildItem $Replace
                $CurrentDateTime = $replaceInfo.CreationTime
            } catch {
                return
            }
        } else {
            if ($Time -ne "") {
                $CurrentDateTime = [DateTime]::Parse($Time)
            } else {
                $CurrentDateTime = Get-Date            
            }
        }
    }
    process {
        if ($pscmdlet.ShouldProcess($FileName)) {
            if (test-path $FileName) {
                $fsInfo = Get-ChildItem $FileName
                Update-FileSystemInfo($fsInfo)
            }
            else {
                if (!$Create.IsPresent) {
                    $fsInfo = Touch-NewFile($FileName)
                    $fsInfo = Get-ChildItem $FileName
                    Update-FileSystemInfo($fsInfo)
                }
            }
        }
        $fsInfo = $null
    }
    end {
    }
}

# Initialize-File naming sucks for the 'touch' command but makes sense in the 
# verb list and passes loading without errors, but lets alias to 'touch-file', ok!
# Not setting alias to 'touch' to avoid 'hidding' your cygwn touch.exe, etc..., do 
# that in your profile if you are not using another version of Touch on your system.
Set-Alias Touch-File Initialize-File -Scope Global
# --------------------------------------------------------------------------------------------
$NL = [System.Environment]::NewLine
Function Create-FileInfo() {
    Param( [string]$href, [int]$bytes=0, [int]$timestamp=0, [string]$checksum=$null, 
           [string]$checksumAlgorithm
    )
    if ($checksumAlgorithm -notin "sha512,sha384,sha256,sha1") {
        Write-Debug "Unsupported checksum algorithm $checksumAlgorithm on $href"
        $checksum=$null
        $checksumAlgorithm=$null
    }
     
    $prop=[ordered]@{
            href=$href; bytes=$bytes; 
            timestamp=([TimeZone]::CurrentTimeZone.ToLocalTime('1/1/1970').AddSeconds($timestamp)); 
            checksum=$checksum;
            checksumAlgorithm=$checksumAlgorithm;
        }
    New-Object -TypeName PSObject -Prop $prop

}

Function Test-DownloadNeeded() {
    Param( [string]$localFile, [PSObject]$remoteFile )
    if ((Test-Path $localFile) -eq $false) {
        $True
    } else {
        $info = Get-Item $localFile
        if ($info.Length -ne $remoteFile.bytes) {
            $True
        } else {
            $False
        }
    }
}

Function Test-DownloadRequested([PSObject]$RepoEntry,[int]$numDays=$DaysBack) {
    $RepoEntry.timestamp.AddDays($numDays) -ge (Get-Date)
}

if ($DeltaZip -ne "") {
    if ( (split-path -Parent $DeltaZip) -eq "" ) {
        $DeltaZip = Join-Path (Get-Location) $DeltaZip
    } else {
        $DeltaZip = Join-Path (Resolve-Path (Split-Path -Parent $DeltaZip)) (Split-Path -Leaf $DeltaZip)
    }
    Add-Type -AssemblyName System.Io.Compression.Filesystem
    $mode="Create"
    if ( (Test-Path $DeltaZip) -eq $True) {
        $mode="Update"
    } 
    try {
        $DeltaZipObj = [System.IO.Compression.ZipFile]::Open($DeltaZip,$mode)
        Write-Host "Opened delta ZIP file $DeltaZip in '$mode' mode."
    } catch {
        Write-Error ("Cannot open {0} for '{1}': {2}" -f $DeltaZip,$mode,$_.ToString())
        $DeltaZip=$Null
    }
}
Function Add-FileToZip([System.IO.Compression.ZipArchive]$ZipObj=$DeltaZipObj,`
        [string]$LocalPath,[string]$InternalPath) {
    $compressionType="Optimal"
    if ($InternalPath -cmatch "(.rpm$|.gz$|.bz2$|.drpm$|.srpm$)" ) {
        $compressionType="NoCompression"; # system.io.compression.compressionlevel
    }
    if ( $ZipObj -ne "" ) {
        try {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ZipObj, $localPath,`
                $InternalPath,$compressionType) | Out-Null
        } catch {
            Write-Error ("Failed to add $InternalPath to the ZIP file: {0}" -f $_.ToString())
            $ZipObj.Dispose()
        }
    
    }
}

Function Process-DownloadQueue([string]$BaseURI="$MirrorRoot/$Repo",[System.Collections.Queue]$RelativeURIQueue, [string]$MirrorFolder=(Get-Location),[bool]$Clobber=$False) {
    $entryTotal=$URIsToGet.Count
    $entryCurrent=1
    $totalBytes = 0
    $RelativeURIQueue |% { $totalBytes += $_.bytes }
    $bytesSoFar=0
    $totalURIs=$RelativeURIQueue.Count
    while ($RelativeURIQueue.Count -gt 0) {
        Write-Debug ("There are {0} items in the download queue." -f $URIsToGet.Count)
        $nextURI = $RelativeURIQueue.Dequeue()
        $localFile = (join-path $MirrorFolder $nextURI.href)
        $perc = ([int]($bytesSoFar * 100.0 / $totalBytes))
        Write-Progress -id 0 -Activity "Download URIs" `
                -Status ("Downloading {0} [{1} of {2}]" -f $nextURI.href,$entryCurrent,$totalURIs) `
                -PercentComplete $perc
            
        if ((Test-Path $localFile) -eq $True) {
            if ($Clobber -eq $True) {
                Remove-Item $localFile
            } else {
                continue
            }
        }
        $localPath = (split-path -Parent $localFile)
        if ( (Test-Path $localPath) -eq $False) {
            mkdir $localPath  | Out-Null
        }
        try { 
            # mkdir (split-path $nextURI -parent) -force | out-null
            $ProgressPreference = "silentlyContinue"
            $response = Invoke-WebRequest  -Uri ("$BaseURI/{0}" -f $nextURI.href) -OutFile "$localFile"
            $ProgressPreference = "Continue"
            $entryCurrent+=1
        } catch {
            Write-Error ( "Error downloading {0}. Requeueing" -f $nextURI.href)
            $RelativeURIQueue.Enqueue( $nextURI )
        }
        if ($DeltaZip -ne "") {
            Add-FileToZip -LocalPath $localFile -InternalPath $nextURI.href
        }
        $bytesSoFar += $nextURI.bytes
    }
    
    Write-Progress -id 0 -Activity "Download URIs" -Completed
}


try {
    $outfile = join-path $mirrorFolder $repomd
    mkdir (split-path -Parent $outfile) -force | out-Null
    $response = Invoke-WebRequest -Uri "$MirrorRoot/$Repo/$repomd" -OutFile $outfile
    $repoXML = [xml] (Get-Content $outfile)
} catch {
    Write-Error ("Failed to download {0}: {1}" -f $repomd,$_.toString() )
    exit 1 
}
if ($DeltaZip -ne "") {
    Add-FileToZip -InternalPath $repomd -LocalPath (join-path $mirrorFolder $repomd)
}
$repoXML.repomd.data |% {
    $info = Create-FileInfo -href $_.location.href -bytes $_.size `
                            -timestamp $_.timestamp -checksum $_.checksum
    $URIsToGet.Enqueue( $info ) | Out-Null
    if ($_.type -eq 'primary') {
        $FilesToExpand.Enqueue( $info ) | Out-Null
    }
}

if ($DeltaZip -ne "") {
    $ZipList = New-Object System.Collections.ArrayList
    $URIsToGet |% { $ZipList.Add($_) | Out-Null }
}
Process-DownloadQueue -RelativeURIQueue $URIsToGet -Clobber $True

Write-Host "Parsing the metadata for files - this might take a moment"
foreach ($info in $FilesToExpand) {
    $file = $info.href
    Write-Debug "Expand $file"
    $nogz = (join-path $mirrorFolder ($file -replace ".gz",""))
    Expand-Gzip $file -NewName $nogz
    $sr = New-Object System.IO.StreamReader($nogz)
    $packageXML=""
    $preamble=""
    $xml = New-Object XML
    # approach #1 - just suck in the whole XML which is likely HUGE and slow to parse
    # approach #2 - try to make a terrible, by-hand extractor of XML data
    # approach #3 - suck out just one record at a time, treat it like xml, and move on - SAX like
    # Below is approach #3, but we have to be somewhat aware of the XML structure/tags
    # with some band-aids to avoid dealing with namespaces
    while (($s = $sr.ReadLine()) -ne $null) { 
        if ($s -match "<\?xml") { $preamble += "$s$NL"; continue }
        if ($s -match "<package( |>)" ) {
            $packageXML=$preamble  + $s + $NL
            continue
        }
        if ($packageXML.Length -gt 0) {
            # rather than ensure that namespaces are imported, we doctor them
            # up to just look like normal tags.  Repeat after me: "Not evil"
            $s = $s -replace "<rpm:","<rpm-" -replace "</rpm:","</rpm-"; 
            $packageXML += $s + $NL
        }
        if ($s -match "</package>") {
            try {
                $xml.LoadXml( $packageXML )
                $info = Create-FileInfo -href $xml.package.location.href -bytes $xml.package.size.package `
                                        -timestamp $xml.package.time.file -checksum $xml.package.checksum.'#text'
                $packageXML=""; # stop recording now that it's blank
                if (( Test-DownloadNeeded -localFile (Join-Path $mirrorFolder $info.href) -remoteFile $info) -eq $True) {
                    $URIsToGet.Enqueue($info)
                    Write-Debug ("Queued {0}" -f $info.href)
                } elseif ($DeltaZip -ne "" -and (Test-DownloadRequested -RepoEntry $info -numDays $DaysBack) ) {
                    Write-Verbose("Queued {0} because it was modified in the last {1} days." -f `
                        (Split-Path -Leaf $info.href),$DaysBack)
                    # we only get this far if it has already been successfully downloaded
                    Add-FileToZip -LocalPath (Join-Path $mirrorFolder $info.href) -InternalPath $info.href
                } else {
                    #Write-Host "Skipped {0}" -f $info.href)
                }
                Remove-Variable info
            } catch {
                Write-Error "Invalid XML: $xml"
                Write-Error ("Error: {0}" -f $_.ToString())
                $packageXML=""
            }
        }
    }
    $sr.Close()
    Remove-Item $nogz
}

Process-DownloadQueue -RelativeURIQueue $URIsToGet -Clobber $True -BaseURI "$MirrorRoot/$Repo"
if ($DeltaZip -ne "") {
    $DeltaZipObj.Dispose()
    Write-Host "Deltas from this session are in $DeltaZip"
}

