<#
.SYNOPSIS 

    Mirror a YUM repository without having a Linux machine, even host the mirror on IIS. 

.DESCRIPTION

    Some corporate networks are extremely reluctant to give end-point control to arbitrary
    users.  If your job is to patch Linux machines that are disconnected from the Internet,
    it can be just a little difficult to get updates as they appear in a YUM repository
    and copied into your disconnected lab. 
      
    This program will connect to the repository, pull down the catalog, and compare the local
    files with the remote files.  New files are pulled down.  If the delta ZIPs are enabled,
    then a ZIP file is created with the catalog and all new RPMs, including SRPM and Delta RPMS.  
    That ZIP file can just be laid on top of an existing
    repository on the disconnected network and hosted by any web server.  Be sure that
    any web server setup has a default MIME type that tags files as application/octet-stream.
    The DaysBack command line option will put a copy of all downloads created in the last few days 
    into the file name computed for delta ZIPs, even if they are already cached locally.  

    The initial mirroring of a repository can consume a lot of bandwidth.  Tens or even a hundred 
    gigabytes.  This tool makes no effort to see if you have sufficient space before starting,
    so pick a non-system disk for your target and have lots of space available.  Also consider
    which remote repository will be your source, and try to choose a content distribution/delivery
    network during the initial mirror.  The source can be changed after the initial sync because
    all files should be the same across mirror sites.

    Note that files which have been removed from the remote repository may be deleted from the
    local cache, they will not be deleted from any offline systems. 

    Regarding the mirroring of Red Hat repositories, there is a Catch-22 here.  At some point, 
    a Red Hat system must be registered and subscribed to a valid channel.  The entitlement
    certificate must be converted and copied to a Windows system.  At that point, updates can
    be pulled from a Windows system so long as the entitlement is active.  The main objective
    is to avoid having to leave a Linux system connected to the Internet, becoming a target of
    infection and tampering.  The certificate will need to be re-issued every year on the date 
    that the maintenance contract is renewed.  It is strongly recommended that you maintain
    a tight list of systems which may pull from the offline repository mirror, punishing those who
    cause you to violate your license agreement.  A technical access control measure would also
    be appropriate.  Ideally, this mirror will feed only one system on a network.  If more than a few 
    systems need to pull updates regularly, please consider purchasing a Red Hat Satellite License and
    follow their advice for maintaining offline systems.  Also consider going through the effort
    (and cost) in your organization to continuously run and maintain an online copy of Red Hat Linux, 
    where the YUM command can easily dump a copy of updated RPMs to a folder of your choice, making
    updates significantly easier than this process.

.Parameter Repository

    The shortName (see -ListRepositories) of a single repository to update.  All others
    are ignored.

.Parameter ListRepositories

    Parse the preferences file and list the available repositories, which will be presented
    as objects of shortName,title.


.Parameter RedHatEntitlement

    A PFX certificate from an entitled Red Hat system, which is naturally in PEM format.  Use this 
    in conjunction with URIs from the YUM repo file in /etc/yum.repo.d/redhat.repo.  The PEM formatted
    x.509 certificate is in /etc/pki/entitlement and can be converted with OpenSSL with
       openssl pkcs12 -export -in 722229339238328485.pem -inkey 722229339238328485-pem.key \
           -out 722229339238328485.pfx

    When prompted to enter an Export Password, just press Enter (no password) for both entries.
    You will of course need to use PEM and key file names from your system.  Once converted, the entitlement
    will need copied out of a working Red Hat system to the Windows machine.

    WARNING!  Be aware that you are solely responsible for compliance with Red Hat licensing.
    Do not distribute patches to systems which are unlicensed or for which you are not directly
    responsible for patching.  The author of this script is not liable or complicit in attempts
    to violate your agreed upon license with Red Hat.  Be honorable.  

    Note: Not currently implemented

.Parameter DaysBack

    After updating the catalog from the mirror site, add all files found that are
    newer than the specified number of days to the ZIP file specified with -DeltaZip.
    The -DeltaZip option must be specified.  This is good for "catching up" a secondary
    offline system that may have missed an update CD.
    
    A number between 0 (just what is new during this run) and 90 (inclusive).  Whole days
    only and it is 24 hours from the time of execution.  So a value of 1 at 3pm will pull
    all deltas that were not downloaded and, in addition, all files added to the repository
    starting at 3pm the day before.

.Parameter PreferencesFile

    The file where preferences and a mirror list are present.  This is a JSON file.
    These global parameters must be defined:
       * cacheRootFolder - location for files already retrieved
       * interFileDelayMilliSeconds - delay between file requests, 0 for no delay
       * deltaFolder - top level location for all delta files that will cross the air gap
       * deltasEnabled - global parameter to enable or disable delta files
       * deltaMaxMegaBytes - maximum size of a ZIP file before creating a new one (usually 4G)
       * logFile - file where detailed reporting goes in case further analysis is needed
    One or more mirrors are present, each with these parameters:
       * title - long title to show the user during processing
       * shortName - lowercase, no spaces name to use in creating delta files or subdirectories
       * mirrorListURI - URI to get mirrors for a distribution - do not use if specifiying remoteRootURIs
       * remoteRootURIs - full URI to get repodata and packages - repodata should be a subfolder
       * packageList - a list of short package titles to get instead of the whole archive, if on the server
       * enabled - if true, mirror this repo, but if false, skip it - good to keep unused configurations around
    Note that if delta files are enabled, they will be named:
       <deltasFolder>/<shortName>-%yyyyMMdd%-<idx>.zip
    where %yyyyMMdd% is parsed as the current date and <idx> is an incremental index in case the 
    ZIP file tries to get bigger than deltaMaxMegaBytes.
    
    The logFile configuration item also accepts the %yyyyMMdd% value to allow for a dedicated
    log file per day.

    The cacheFolder for a particular mirror is <cacheRootFolder>/<shortName>.

    If using the packageList parameter to restrict files that will be downloaded, obtain the 
    needed list of packages by asking an existing system what is installed now.
    Files added to the system by something other than anaconda during install or subsequent updates
    can be found with this Linux command, which dumps out the needed JSON:
        for f in /var/lib/yum/yumdb/*/*/from_repo; do egrep -v -e '(anaconda|updates)' --silent $f && \
            dirname "$f" | sed -e 's/.*\/[a-z0-9]*-//; s/-[0-9][\.0-9]*.*//'; done |awk \
            'BEGIN{print "\"packageList\": ["; p=""} END {print p; print "];"} {if(p) print p  ","; p="   \"" $0 "\"" }'
    While all of the packages on a particular system can be found with this Linux command which
    again dumps out the needed JSON:
        for f in /var/lib/yum/yumdb/*/*; do echo "$f" | sed -e 's/.*\/[a-z0-9]*-//; s/-[0-9][\.0-9]*.*//'; \
            done |awk 'BEGIN{print "\"packageList\": ["; p=""} END {print p; print "];"}
            {if(p) print p  ","; p="   \"" $0 "\"" }'
    Caution - files added directly with RPM will be ignored since it is presumed that another
    method is used to obtain those files when they are updated.

.Parameter NoDeltaZip
    
    Override the global setting deltasEnabled to disable delta ZIPs.  Great when combined with
    -Repository after adding a new repo.  

.Parameter FilePackageListing
    
    A file on the file system that lists the exact packages to mirror.  Alternatively,
    the mirror parameter packageList can be used to restrict which files are
    mirrored from a very large repository.  Great for offline systems that don't need
    everything.

.Parameter Verbose

    This common parameter shows more about what is going on during
    the evaluate and download process. This option also shows where a particular 
    preference is set or overridden.

.LINK

    https://github.com/zerolagtime/Powershell
       
.EXAMPLE

    .\Mirror-YumRepo.ps1 -NoDeltaZip

    For the first time the script is run with a new repository configured.
    Read the list of mirrors in the preferences file.  For each mirror, download updates 
    into the cache folder, but do not create a delta ZIP as it would be easier to just
    copy the whole mirrored folder.

.EXAMPLE

    .\Mirror-YumRepo.ps1

    Day 2 of the program reads the repositories.json file in the same folder as the
    script and updates all of the mirrors.  One could also just right-click on the PS1 file
    and select "Run with PowerShell."

.EXAMPLE
    
    .\Mirror-YumRepo.ps1 -DaysBack 30

    Assuming that delta ZIP creation is enabled in the configuration file, go through each
    mirror and update it, grabbing all updates from the last 30 days, even if they are already
    cached.  Good for that system that might have missed intermediate updates, creating a rollup.

.EXAMPLE
    .\Mirror-YumRepo.ps1 -Repository centos7-os

    Search the preferences file for a mirror whose short name is "centos7-os" and do normal
    mirroring duties, but just for that repository.

.Notes 
    Author		: Charlie Todd <zerolagtime@gmail.com>
    Version		: 2.0 - 2017/07/026
    Copyright   : Copyright 2017 Charlie Todd
                  Licensed under the Apache License, Version 2.0 (the "License");
    Permissions : Local execution policies may prohibit you from
                  running this program.  In that case, open a 
                  PowerShell window and type:
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
                  Additionally, this script can be called from a shortcut with
                  the destination set to
                    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass some_folder\Mirror-YumRepo.ps1
    Credit      : GZIP compress and decompress - Copyright 2013 Robert Nees - Apache License 2.0
                : Jeffery Hicks at mcpmag.com for his PowerShell File Frontier article on ZIP files
#>
# Add -WhatIf support
[CmdletBinding(SupportsShouldProcess=$True)]
Param(
    [parameter()][uri]$MirrorRoot,
    [parameter()][string]$Repository,
    [switch]$ListRepositories,
    [ValidateRange(0,90)]
        [parameter()][int]$DaysBack,
    [ValidateScript({(Test-Path $_) -and (Get-Content $_ | ConvertFrom-Json)})]
    [ValidatePattern("\.json$")]
    [parameter(HelpMessage="Only properly formatted JSON files are permitted.  Use the example JSON to get started.")]
        [string]$PreferencesFile,
    [parameter()][switch]$NoDeltaZip,
    [string []]$FilePackageListing,
    $Command
)
Set-StrictMode -Version 4.0
#Requires -Version 4
#$DebugPreference="Continue"
# this list of variables also constrains what can be set in the preferences file

$Defaults = @{
}
# find modules that ship with this core package
$env:psmodulepath =$env:psmodulepath + ";" + (join-path $PSScriptRoot "Modules")

$NL = [System.Environment]::NewLine
####################################################################################
# main() function.  treat it as a function so that the reader can follow along at the top
# and see the supporting functions later.  The last line of the Script is a call to this function.
Function Main-Mirror-YumRepo() {
    Param(
        [Parameter(Mandatory=$True)][string]$PrefFile
    )
    $config = Parse-PreferencesJSON($prefFile)
    $repositories = $config.mirrors | where enabled -eq $true | select-object -expandProperty shortName; # an array more than likely
    if ($Repository) {
        if ($Repository -in $repositories) {
            $repositories = $Repository
        } else {
            throw "No such repository $Respository - valid list is: $($repositories -join ', ')"
        }
    }
    $repoIdx = 0.5
    foreach ($repo in $repositories) {
        Write-Progress -id 1 -activity "Mirroring $($repositories.Count) YUM repositories" -status "Processing mirror $repo" `
            -PercentComplete ([int]($repoIdx * 100 / $repositories.count)); $repoIdx++
        $mirrorConfig = $config.mirrors | where shortName -eq $repo | select -First 1
        $deltaFiles = Update-MirrorSite -GlobalConfig $config.global -MirrorConfig $mirrorConfig
        if ($config.deltasEnabled) {
            try {
                Generate-DeltaZip -ZipFolder $config.deltaFolder -shortName $repo -Files $deltaFiles -maxBytes ($config.deltaMaxMegaBytes*1024*1024)
            } catch {
                Write-Warning "Error creating a delta ZIP.  Sleeping for 10 seconds to allow more updates to be cancelled"
                Start-Sleep -Seconds 10
            }
        }
    }
    Write-Progress -activity "ignored" -id 1 -Completed
}

Function Update-MirrorSite($GlobalConfig,$MirrorConfig) {
    $files=new-object System.Collections.ArrayList
    if ($mirrorConfig.MirrorListURI) {
        $mirrorSite=Get-YumMirror -MirrorURI $MirrorConfig.mirrorListURI 
        $mirrorConfig | Add-Member -NotePropertyName "RemoteRootURIs" -NotePropertyValue @($mirrorSite)
    } else { 
        $mirrorSite = $mirrorConfig.remoteRootURIs[0]
    }
    $mirrorConfig | Add-Member -NotePropertyName "WebSession" -NotePropertyValue (New-Object Microsoft.PowerShell.Commands.WebRequestSession)
    $catalogFiles = Get-YumCatalogFiles -mirrorConfig $MirrorConfig -cacheFolder (join-path $GlobalConfig.cacheRootFolder $mirrorConfig.shortName)
    $catalogFiles |% {$files.Add($_) | out-null}
    $missingFiles = Identify-MissingDownloads -catalogFiles $catalogFiles 
    Get-MissingDownloads -CacheFolder (join-path $GlobalConfig.cacheRootFolder $mirrorConfig.shortName) `
        -globalConfig $GlobalConfig
}

Function Get-YumCatalogFiles($cacheFolder,$mirrorConfig) {
    $catalogPath=join-path $cacheFolder "repodata"
    if ( (test-path $catalogPath) -eq $False) {
        Write-Verbose "Creating repodata folder $catalogPath"
        new-item -ItemType Container $catalogPath | out-null
    }
    $existingCatalog = get-childitem $catalogPath 
    $files=new-object System.Collections.ArrayList
    $relpath = "repodata/repomd.xml"
    $repoMDURI=Join-Uri $mirrorConfig.RemoteRootURIs[0] $relpath
    $repoMDURI | Add-Member -MemberType Noteproperty -Name "relativePath" -Value $relpath
    $repoMDURI | Add-Member -MemberType Noteproperty -Name "rootURI" -value (Join-Uri -base $mirrorConfig.remoterootURIs[0] -path (Split-Path -Parent $relpath))
    $existingCatalog |% { Remove-Item -whatif $_ }
    $files = Get-MissingDownloads -CacheFolder $cacheFolder -globalConfig $mirrorConfig -URIs $repoMDURI
    return $files
}

Function Identify-MissingDownloads($catalogFiles) {
return $null
    $items=new-object System.Collections.ArrayList
        $props = @{
            "URI"= $uri;
            "RelPath"= $relPath;
            "Bytes"= $bytes;
        }
        $obj = new-object -TypeName System.Management.Automation.PSCustomObject -Property $props
        $items.Add($obj) | out-null
    return $items
}

Function Get-MissingDownloads($CacheFolder,$globalConfig,$URIs) {
    # use workflows to parallelize the download process
    # https://blogs.technet.microsoft.com/heyscriptingguy/2012/12/26/powershell-workflows-the-basics/
    Workflow Parallel-Downloads {
        Param([uri []]$URIs,[string]$LocalPath,$session)
        $destinations = @{}
        $URIs.relativePath |% { $loc = join-path $localpath $_; $destinations.$_ = $loc }
        foreach -parallel  -throttleLimit $globalConfig.simultaneousDownloads ($uri in $URIs) {
            Get-URI -URIs $uri -destinations ($destinations | where key -eq $uri | select-object -ExpandProperty Value)
        }
    }
    $URIs.relativePath | split-path -parent | Sort-Object -Unique |% { mkdir -Force $_  -Verbose| out-null }
    Parallel-Downloads -URIs $URIs -LocalPath $cachefolder -session $GlobalConfig.websession
    return $destinations.value
}

Function Get-URI($URIs,$destinations) {
    $proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
    if ($proxyaddr) {
        Start-BitsTransfer -Source $URIs -Destination $destinations -TransferPolicy BelowCap -TransferType Download -ErrorAction Inquire  -ProxyList $proxyAddr
    } else {
        Start-BitsTransfer -Source $URIs -Destination $destinations -TransferPolicy BelowCap -TransferType Download -ErrorAction Inquire
    }
}

Function Ignored() {

    #=======================================
    if ( (Import-Preferences -PreferencesFile $prefFile) -eq $False ) {
            Write-Error "There was an error reading preferences from $prefFile.  Use -ClearPreferences."
            exit(1)
        } 
    Write-Verbose "Preferences successfully read in from $prefFile"
    if ( (Validate-Preferences) -eq $False ) {
        Write-Error "One or more parameters had errors.  See: Get-Help Mirror-YumRepos.ps1"
        exit(1)
    }
    if ($SavePreferences -eq $True) {
        $Defaults.MirrorRoot = $MirrorRoot
        $Defaults.Repository = $Repository
        $Defaults.CacheFolder = $CacheFolder
        $Defaults.DeltaZip = $DeltaZip
        $Defaults.Offline = [bool]$Offline
        ConvertTo-Json $Defaults | Out-File $prefFile
    }

    $URIsToGet = New-Object System.Collections.Queue
    $FilesToExpand = New-Object System.Collections.Queue
    $FoldersWithPackages = New-Object System.Collections.Hashtable
    $AllRemotePackages = New-Object System.Collections.ArrayList

    if ($DeltaZip -ne "" -and $WhatIfPreference.IsPresent) {
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
            #Trap {Remove-Variable DeltaZipObj; "Error caught: $_"; break }
            Write-Host "Opened delta ZIP file $DeltaZip in '$mode' mode."
        } catch {
            Write-Error ("Cannot open {0} for '{1}': {2}" -f $DeltaZip,$mode,$_.ToString())
            $DeltaZip=$Null
        }
    }

    try {
        $FoldersWithPackages.Add( (Split-Path -Parent $repomd), $True) | Out-Null
        $AllRemotePackages.Add($repomd) | Out-Null
        $outfile = join-path $CacheFolder $repomd
        mkdir (split-path -Parent $outfile) -force | out-Null
        if ( $Offline -eq $True -and (Test-Path -Path $outfile -PathType Leaf) -eq $True ) {
            Write-Verbose "Offline mode requested.  Repo index available at $outfile"
        } else { 
            Write-Debug "Attempting to download the repository index to $outfile"
            $repoUri = [uri](Join-Uri ([uri]$MirrorRoot).AbsoluteUri $Repository $repomd)
            Write-Debug ( "Starting file download from {0}" -f $repoUri.AbsoluteUri)
            $response = Invoke-WebRequest -Uri $repoUri -OutFile $outfile
        }
        $repoXML = [xml] (Get-Content $outfile)
    } catch {
        Write-Error ("Failed to download {0}: {1}" -f $repomd,$_.toString() )
        exit 1 
    }
    if ($DeltaZip -ne "") {
        Delete-FileFromZip -ZipObj $DeltaZipObj -InternalPath $repomd
        Add-FileToZip -InternalPath $repomd -LocalPath (join-path $CacheFolder $repomd)
    }
    $repoXML.repomd.data |% {
        if ( ($_ | Get-Member size) -ne $Null ) { $size = $_.size } else {$size = 0}; # RHEL 5 file has no size attrib
        $info = Create-FileInfo -href $_.location.href -bytes $size `
                                -timestamp $_.timestamp -checksum $_.checksum
        $AllRemotePackages.Add($_.location.href) | Out-Null
        if ($Offline) {
            if ( (Test-Path (Join-Path $CacheFolder $info.href)) -eq $False ) {
                Write-Error ("The offline repository is missing {0}.  Processing aborted." -f $info.href)
                return $False
            }
        } else {
            if (Test-DownloadNeeded -localFile (Join-Path $CacheFolder $info.href) -remoteFile $info) {
                Write-Verbose ("Queueing {0} for download" -f $info.href) 
                $URIsToGet.Enqueue( $info ) | Out-Null
            } else {
                Write-Verbose ("No need to download {0} as the local copy is up to date." -f $info.href)
            }
        }
        if ($_.type -eq 'primary') {
            $FilesToExpand.Enqueue( $info ) | Out-Null
        }
    }

    if ($DeltaZip -ne "") {
        $ZipList = New-Object System.Collections.ArrayList
        $URIsToGet |% { $ZipList.Add($_) | Out-Null }
    }
    Process-DownloadQueue -RelativeURIQueue $URIsToGet
    if ($DeltaZipObj) {
        $DeltaZipObj.Dispose()
    } 

    Write-Host "Parsing the metadata for files - this might take a moment"
    $catalogNum=1
    foreach ($info in $FilesToExpand) {
        $file = Join-Path $CacheFolder $info.href
        Write-Debug "Expand $file"
        $nogz = $file -replace ".gz",""
        Write-Debug "UnGZIP $file to $nogz"
        try {
            Expand-Gzip $file -NewName $nogz
            Write-Debug "Open $nogz for stream reading"
        } catch {
            Write-Error ("Error decompressing and reading ${file}: {0}" -f $_.ToString() )
            Start-Sleep -Seconds 3
            continue
        }
        try {
            $sr = New-Object System.IO.StreamReader($nogz)
            trap { $sr.Finalize; Write-Host "StreamReader closed up."; return }
        } catch {
            Write-Error ("Error decompressing and reading ${nogz}: {0}" -f $_.ToString() )
            Start-Sleep -Seconds 3
            continue
        }    
        $packageXML=""
        $preamble=""
        $xml = New-Object XML
        $packageNum=0
        $deltaPackages=0
        $line=0; 
        $stat="Looking for packages"
        $gatherLines=$False
        if ($DaysBack -eq 0) {
            $activity = ("Searching through the catalog [{0} of {1}] for packages since last run." -f $catalogNum,$FilesToExpand.Count)
        } else {
            $activity = ("Searching for new packages and those new in the last $DaysBack days in catalog [{0} of {1}]." -f $catalogNum,$FilesToExpand.Count)
        }
        $DebugPreference="Continue"
        # approach #1 - just suck in the whole XML which is likely HUGE and slow to parse
        # approach #2 - try to make a terrible, by-hand extractor of XML data
        # approach #3 - suck out just one record at a time, treat it like xml, and move on - SAX like
        # Below is approach #3, but we have to be somewhat aware of the XML structure/tags
        # with some band-aids to avoid dealing with namespaces
        while (($s = $sr.ReadLine()) -ne $null) {
            $line+=1
            $perc = $sr.BaseStream.Position * 100.0 / $sr.BaseStream.Length
            if ( ($line % 250) -eq 0 ) {
                Write-Progress -id 10 -Activity $activity -Status $stat -PercentComplete $perc 
            }
            if ($s -match "<\?xml") { $preamble += "$s$NL"; continue }
            if ($s -match "<name>([^<]+)</name>") { $stat += " Package " + $matches[1] }
            if ($s -match "<package( |>)" ) {
                #Start-Timer -Tag "PackageSnarf"
                $gatherLines=$True
                if ($DaysBack -eq 0) {
                    $stat = ("Examining package {0}, found {1} new packages to download." -f $packageNum,$URIsToGet.Count)
                } else {
                    $stat = ("Examining package {0}, found {1} new package, added {2} historical packages." -f `
                        $packageNum,$URIsToGet.Count,$deltaPackages)
                }
                Write-Progress -id 10 -Activity $activity -Status $stat -PercentComplete $perc 
                $packageXML=$preamble  + $s + $NL
                $packageNum+=1
                continue
            }
            if ( $s -match "(<rpm:requires[^>]*>|<rpm:conflicts[^>]*>|<rpm:provides[^>]*>)" ) {
                $gatherLines = $False
                $s = $s -replace $matches[1],""
                $packageXML +=  $s + $NL
            }
            if ( $s -match "(</rpm:requires>|</rpm:requires>|</rpm:provides>)" ) {
                $gatherLines = $True
                $s = $s -replace $matches[1],""
            }
            if ($gatherLines -eq $True) {
                $packageXML += $s + $NL
            }
            if ($s -match "</package>" -and $gatherLines -eq $True) {
                #Write-Debug "XML=$packageXML"
                $gatherLines=$False
                #$delta=Stop-Timer -Tag "PackageSnarf"
                try {
                    #Start-Timer -Tag "PackageParse"
                    # rather than ensure that namespaces are imported, we doctor them
                    # up to just look like normal tags.  Repeat after me: "Not evil, but faster and cleaner code"
                    # since strings are easier to mangle than multiple namespace XML structures are to parse.
                    $packageXML = $packageXML  -replace "<rpm:","<rpm-" -replace "</rpm:","</rpm-"; 
                    Write-Progress -id 10 -Activity $activity -Status $stat -PercentComplete $perc
                    $xml.LoadXml( $packageXML )
                    #$delta=Stop-Timer -Tag "PackageParse" -Description $xml.package.name
                    $info = Create-FileInfo -href $xml.package.location.href -bytes $xml.package.size.package `
                                            -timestamp $xml.package.time.file -checksum $xml.package.checksum.'#text' `
                                            -checksumAlgorithm $xml.package.checksum.type
                    # add the folder with packages to a list of folders we can compare later
                    $FoldersWithPackages[(Split-Path -Parent $xml.package.location.href)] = $True # auto-duplicate remover  
                    $AllRemotePackages.Add($xml.package.location.href) | Out-Null # easily searched with $AllRemotePackages.Contains($file)
                    $packageXML=""; # stop recording now that it's blank
                    if (( Test-DownloadNeeded -localFile (Join-Path $CacheFolder $info.href) -remoteFile $info) -eq $True) {
                        $URIsToGet.Enqueue($info) | Out-Null 
                        Write-Debug ("Queued {0}" -f $info.href)
                    } elseif ($DeltaZip -ne "" -and (Test-DownloadRequested -RepoEntry $info -numDays $DaysBack) ) {
                        Write-Verbose("Queued {0} because it was modified in the last {1} days." -f `
                            (Split-Path -Leaf $info.href),$DaysBack)
                        # we only get this far if it has already been successfully downloaded
                        Delete-FileFromZip -ZipObj $DeltaZipObj -InternalPath $info.href
                        Add-FileToZip -LocalPath (Join-Path $CacheFolder $info.href) -InternalPath $info.href | Out-Null
                        $deltaPackages+=1
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
        $DebugPreference="SilentlyContinue"
        $sr.Close()
        Write-Progress -id 10 -Activity "Reading in packages" -Completed 
        Remove-Item $nogz
        $catalogNum+=1
    }
    if ($TrimCache) {
        Write-Verbose "Trimming the cache of the local repository as requested."
        $numRemoved = Expire-ObsoleteCache  -LocalFileRoot $CacheFolder -FolderList $FoldersWithPackages -RemoteFileList $AllRemotePackages
    }
    try {
        if ($DeltaZip -ne "") {
            $DeltaZipObj = [System.IO.Compression.ZipFile]::Open($DeltaZip,"Update")
        }
    } catch {
        Write-Warning ("Could not re-open the zip file ${DeltaZip}: {0}" -f $_.ToString())
    }
    Process-DownloadQueue -RelativeURIQueue $URIsToGet -Clobber $True -BaseURI (Join-Uri ([uri]$MirrorRoot).AbsoluteUri $Repository)

    if ($DeltaZip -ne "") {
        $DeltaZipObj.Dispose()
        Write-Host "Deltas from this session are in $DeltaZip"
    }
    Write-Host "Processing completed."

}; ### END of Main-Mirror-YumRepo Function

Function Get-PreferencesFile([string]$DefaultFile) {
    Write-Verbose "here = $PSScriptRoot"
    if (! $DefaultFile) {
        $DefaultFile = (join-path $PSScriptRoot "repositories.json")    
    }
    if ( (Test-Path $DefaultFile) -eq $true ) {
        return $DefaultFile
    }
    throw "Cannot locate the preferences file in $DefaultFile"
}

Function Generate-DeltaZip ($ZipFolder, $shortName, $Files, $maxBytes=$null) {
    $zipFileNum=1
    $ZipFile = Replace-DateString (join-uri $ZipFolder "$shortName-%yyyyMMdd%-$zipFileNum.zip")
    if (test-path $ZipFile -PathType Leaf) {
        $size = (get-item $zipfile).length
    } else {
        $size = 2048; # minimum ZIP directory size
    }
    try {
        $handle = Open-Zip($ZipFile);
    } catch {
        Write-Warning "Could not open ZIP file $ZipFile - $($_.exception)"
        throw "Could not open ZIP $ZipFile for writing"
    }
    $fileCount = $Files.Count
    $fileIdx = 1;
    foreach ($f in $Files) {
        $info = get-item $f
        if ($size + $info.length -gt $maxBytes) {
            Close-Zip $handle
            $zipFileNum++
            $ZipFile = Replace-DateString (join-uri $ZipFolder "$shortName-%yyyyMMdd%-$zipFileNum.zip")
            if (test-path $ZipFile -PathType Leaf) {
                $size = (get-item $zipfile).length
            } else {
                $size = 2048; # minimum ZIP directory size
            }
            try {
                $handle = Open-Zip($ZipFile);
            } catch {
                Write-Warning "Could not open ZIP file $ZipFile - $($_.exception)"
                throw "Could not open ZIP $ZipFile for writing"
            }
        }
        try {
            Write-Progress -id 15 -activity "Create Delta Zip $(split-path -leaf $ZipFile)" -status "Adding $f" `
                -percentComplete ([int]($fileIdx*100/$filecount)); $fileIdx++
            New-ZipFileEntry -handle $handle -RelPath (split-path $file -parent) -File $f
        } catch {
            Close-Zip $handle
            Write-Progress -id 15 -activity "a" -complete
            throw "Could not add $f to the ZIP $ZipFile - $($_.exception)"
        }
    }
    Close-Zip $handle
    Write-Progress -id 15 -activity "a" -complete
}

Function Get-YumMirror() {
<#
.SYNOPSIS
Get-YumMirror contacts a mirror server for a list of mirrors and selects one

.DESCRIPTION
The mirrorlist server returns a list of URIs for further mirroring. If
-Quick is provided, one is chosen at random and there may be bandwidth
or high usage on the remote site.  By default, mirrors are chosen at random
until at least one is less than or equal to $MaxMillisecondResponse (200 msec default).

Additionally, if external usage of a mirror shows that the mirror has since
gone down or has become too slow, then the -Not [<uri>] parameter can be used to
exclude that entry.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position=1)][uri]$MirrorURI,
        $webSession=$Null,
        [switch]$Quick,
        [uri []]$Not=$Null,
        [int]$MaxMillisecondResponse=200,
        [uri []]$PredefinedURIs
    )
    if (! $MirrorURI -and $PredefinedURIs.count -eq 0) {
        throw "Get-YumMirror expected either -MirrorURI or -PredefinedURIs"    
    }
    $allResponseTimes = new-object System.Collections.Hashtable
    # internal function to track response time for a remote server
    Function Get-URIResponseTime($URI,$WebSession) {
        Write-Debug "Checking response time for $URI"
        try {
            $t = measure-command { Invoke-WebRequest -uri $URI -WebSession $WebSession -Method Head }
            Write-Verbose "Quick test against $URI took $($t.totalmilliseconds) milliseconds"
            return $t.TotalMilliseconds
        } catch {
            Write-Warning "Unable to contact $($uri.host): $($_.exception)"
            return $null
        }
    }
    Function Test-UriResponseTime($URI, $WebSession) {
        $ms = Get-URIResponseTime -URI $URI -WebSession $WebSession
        $allResponseTimes.$URI = $ms
        if ($ms -eq $null -or $ms -gt $MaxMillisecondResponse) {
            return $false
        }
        return $true
    }
    $url=$null
    $urls = New-Object System.Collections.ArrayList
    Get-Random -SetSeed (get-date -uformat "%s") | out-null
    Write-Progress -Activity "Checking YUM mirror sites" -id 30 -Status "Obtaining the list of mirror sites" -PercentComplete 0
    if (! $PredefinedURIs ) {
        try {
            (Invoke-WebRequest -uri $MirrorURI -WebSession $WebSession) -split "`n" |% { 
                if (($_ -notmatch "^\s*$")) { $urls.add($_) | out-null } 
            }
        } catch {
            Write-Warning "Unable to contact $($uri.host) for a mirror list: $($_.exception)"
            return $null
        }
    } else {
        $PredefinedURIs |% { $urls.add($_) | out-null } 
    }
    $urlCount = $urls.count
    # remove mirrors to skip per the caller's request
    if ($not) {
        $not |% { $urls.Remove($_.AbsoluteUri) } }
    while ($url -eq $Null -and $urls.count -ne 0) {
        $url = get-random -InputObject $urls -Count 1
        if ([uri]$url -eq $not) {
            $url = $Null
            $triesLeft--
        }
        if (! $quick) {
            Write-Progress -Activity "Checking YUM mirror sites" -id 30 -Status "Checking $url" -PercentComplete ([int]($urlcount-$($urls.count))*100/$urlcount)
            $isFastEnough = Test-UriResponseTime -URI $url -WebSession $webSession
            if ($isFastEnough -eq $false) {
                if ($url) {
                    $urls.Remove(([uri]$url).absoluteuri) }
                $url = $null
            }
        }
    }
    Write-Progress -Activity "Checking YUM mirror sites" -id 30 -Completed
    if (!$url) {
        Write-Warning "No suitable mirror could be found.  They are all too slow. Selecting the fastest of the slow."
        $fastest = $allResponseTimes.getenumerator() | sort -Property Value | select-object -expandproperty Name -first 1
        return $fastest
    }
    return ([uri]$url).absoluteURI
}

Function Add-FileToZip([System.IO.Compression.ZipArchive]$ZipObj=$DeltaZipObj,`
        [string]$LocalPath,[string]$InternalPath) {
    $compressionType="Optimal"
    if ($InternalPath -cmatch "(.rpm$|.gz$|.bz2$|.drpm$|.srpm$|.jpg$|.png$|.avi$|.mkv$|.mp4$)" ) {
        $compressionType="NoCompression"; # system.io.compression.compressionlevel
    }
    if ( $ZipObj -ne "" ) {
        try {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ZipObj, $localPath,`
                $InternalPath,$compressionType) | Out-Null
        } catch {
            throw ("Failed to add $InternalPath to the ZIP file: {0}" -f $_.ToString())
        }
    
    }
}

Function Delete-FileFromZip([System.IO.Compression.ZipArchive]$ZipObj=$DeltaZipObj,[string]$InternalPath) {
    if ($DeltaZipObj) {
        $toDelete = New-Object System.Collections.Stack
        $DeltaZipObj.Entries |% {if ($_ -and $_.FullName -eq $InternalPath) {$toDelete.Push($_) } }
        # If the file was not in the ZIP, then there is nothing to do here
        while ($toDelete.Count -gt 0) {
            Write-Verbose "Deleted $InternalPath from the ZIP (probably so it can be added again)"
            ($toDelete.Pop()).Delete()
        }
    } else {
        Write-Debug "Cannot delete $InternalPath from ZIP as the ZIP file is not open"
    }
}

Function Process-DownloadQueue([string]$BaseURI=(Join-Uri ([uri]$MirrorRoot).AbsoluteUri $Repository),`
                [System.Collections.Queue]$RelativeURIQueue, `
                [string]$MirrorFolder=(Get-Location),`
                [bool]$Clobber=$False) {
    $entryTotal=$URIsToGet.Count
    $entryCurrent=1
    $totalBytes = 0
    $RelativeURIQueue |% { $totalBytes += $_.bytes }
    $bytesSoFar=0
    $totalURIs=$RelativeURIQueue.Count
    $skippedURIs=0
    if ($WhatIfPreference.IsPresent) {
        Write-Progress -id 5 -Activity "Download URIs [dry run]" -status "Mock download with 100ms delay between 'downloads'"
        Start-Sleep -Seconds 2
        $totalCount=$RelativeURIQueue.Count;
        $index=0
        while ($RelativeURIQueue.Count -gt 0) {
            $nextURI = $RelativeURIQueue.Dequeue()
            $localFile = split-path -leaf $nextUri
            Write-Progress -id 5 -Activity "Download URIs [dry run]" -status ( "Mock download:" -f $localfile ) -PercentComplete (($index*100.0)/$totalCount)
            Start-Sleep -Milliseconds 100
            $index++
        }
        Write-Progress -id 5 -Activity "Download URIs [dry run]" -status "Mock download completed"
        Start-Sleep -Seconds 2
        Write-Progress -id 5 -Activity "Download URIs [dry run]" -Completed
        return $True
    }
    while ($RelativeURIQueue.Count -gt 0) {
        Write-Debug ("There are {0} items in the download queue." -f $URIsToGet.Count)
        $nextURI = $RelativeURIQueue.Dequeue()
        $localFile = (join-path $CacheFolder $nextURI.href)
        $perc = ([int]($bytesSoFar * 100.0 / $totalBytes))
        Write-Progress -id 5 -Activity "Download URIs" `
                -Status ("Downloading {0} [{1} of {2}]" -f $nextURI.href,$entryCurrent,$totalURIs) `
                -PercentComplete $perc
            
        if ((Test-Path $localFile) -eq $True) {
            if ($Clobber -eq $True) {
                Remove-Item $localFile
            } 
        }
        $localPath = (split-path -Parent $localFile)
        if ( (Test-Path $localPath) -eq $False) {
            mkdir -force $localPath  | Out-Null
        }
        if ($nextURI.local_newer -eq $False) {
            try { 
                # mkdir (split-path $nextURI -parent) -force | out-null
                $ProgressPreference = "silentlyContinue"
                $response = Invoke-WebRequest  -Uri (Join-Uri $BaseURI $nextURI.href) -OutFile "$localFile" -WebSession $ScriptWebSession
                $props = Get-Item $localFile
                $props.LastWriteTime = $nextURI.timestamp
                $props.CreationTime = $nextURI.timestamp
                $ProgressPreference = "Continue"
                if ($VerifyAllChecksums -eq $True -and $nextURI.checksum -ne "" -and $nextURI.checksumAlgorithm -ne "none" ) {
                    Write-Verbose "Verifying checksum on $nextURI.href"
                }
                $entryCurrent+=1
            } catch {
                Write-Error ( "Error downloading {0}. Requeueing" -f $nextURI.href)
                $RelativeURIQueue.Enqueue( $nextURI ) | Out-Null
            }
        } else {
            Write-Verbose ("Local file {0} is the same or newer than the remote file." -f $nextUri.href)
            $skippedURIs += 1
        }
        if ($DeltaZip -ne "") {
            Delete-FileFromZip -ZipObj $DeltaZipObj -InternalPath $nextURI.href
            Add-FileToZip -LocalPath $localFile -InternalPath $nextURI.href
        }
        $bytesSoFar += $nextURI.bytes
    }
    
    Write-Progress -id 5 -Activity "Download URIs" -Completed
    Write-Host ("Downloaded {0} files." -f ($totalURIs - $skippedURIs))
}

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
            If ($Force) {
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
            If ($Force) {
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

Function Ignore-WhatIf() {
    Param(
        [parameter(Mandatory=$True,Position=1)][scriptBlock]$ScriptBlock={$True}
    )
    $oldWhatIf=$WhatifPreference
    $WhatifPreference=$False
    invoke-command $ScriptBlock
    $WhatifPreference=$oldWhatIf
}
# Initialize-File naming sucks for the 'touch' command but makes sense in the 
# verb list and passes loading without errors, but lets alias to 'touch-file', ok!
# Not setting alias to 'touch' to avoid 'hidding' your cygwn touch.exe, etc..., do 
# that in your profile if you are not using another version of Touch on your system.
Ignore-WhatIf { Set-Alias Touch-File Initialize-File -Scope Global }
# --------------------------------------------------------------------------------------------
Function Create-FileInfo() {
    Param( [string]$href, [int]$bytes=0, [int]$timestamp=0, [string]$checksum=$null, 
           [string]$checksumAlgorithm
    )
    if ($checksumAlgorithm -notin "sha512","sha384","sha256","sha1","sha") {
        Write-Debug "Unsupported checksum algorithm $checksumAlgorithm on $href"
        $checksum=$null
        $checksumAlgorithm=$null
    } else {
        if ($checksumAlgorithm -eq "sha") {
            $checksumAlgorithm="sha1"
        }
    }
     
    $prop=[ordered]@{
            href=$href; bytes=$bytes; 
            timestamp=([TimeZone]::CurrentTimeZone.ToLocalTime('1/1/1970').AddSeconds($timestamp)); 
            checksum=$checksum;
            checksumAlgorithm=$checksumAlgorithm;
            mirror_uri=(Join-Uri $MirrorRoot $Repository $href);
            local_newer=$False;
        }
    if ($size -eq 0) {
        try {
            $ProgressPreference = "silentlyContinue"
            $request = Invoke-WebRequest -Uri $prop.mirror_uri.AbsoluteUri -Method HEAD -WebSession $ScriptWebSession
            $prop.bytes = $request.Headers.'Content-Length'
            if (Test-Path -PathType Leaf  (join-path $CacheFolder $prop.href) ) {
                $prop.local_newer = (Get-Item (join-path $CacheFolder $prop.href)).CreationTime -gt (Get-date $request.Headers.'Last-Modified')
            } else {
                $prop.local_newer = $False
            }
            if ($timestamp -eq 0) {
                $prop.timestamp = Get-date $request.Headers.'Last-Modified'
            }
            $ProgressPreference = "Continue"
        } catch {
            $size=0
        }
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
            if ($remoteFile.timestamp -and
                    ($info.LastWriteTime -lt $remoteFile.timestamp)) {
                $True
            } else {
                $False
            }
        }
    }
}


Function Join-Uri {
    # Adapted from poshcode.org/2097 - code is "free to use for public use" - by Joel Bennett
    Param( [Parameter()][System.Uri]$base,
           [Parameter(ValueFromRemainingArguments=$True)][string []] $path
    )
    $ofs="/"; $outUri=""
    if ($base -and $base.AbsoluteUri) {
        $outUri=($base.AbsoluteUri).Trim("/") + "/"
    }
    return [uri]"$outUri$([string]::Join("/", @($path)).TrimStart('/'))"
}

Function Test-DownloadRequested([PSObject]$RepoEntry,[int]$numDays=$DaysBack) {
    $RepoEntry.timestamp.AddDays($numDays) -ge (Get-Date)
}

Function Expire-ObsoleteCache([string]$LocalFileRoot,[System.Collections.Hashtable]$FolderList, [System.Collections.ArrayList]$RemoteFileList) {
    $ToRemoveCount = 0
    $ToRemove = New-Object System.Collections.Queue
    Write-Verbose "Searching local filesystem in $LocalFileRoot for obsolete files"
    foreach ($folder in $FolderList.Keys) {
        $LocalFolder=Join-Path $LocalFileRoot $folder
        Get-ChildItem -File -Recurse $LocalFolder |% { 
            # Get-ChildItem uses backslashes, but URIs used to populate $RemoteFileList uses forward slashes
            $relFile = $_.FullName.Replace("$LocalFileRoot\","") -replace "\\","/"
            if ($RemoteFileList.Contains($relFile) -eq $False) {
                Write-Debug "  Expire: $relFile"
                $ToRemove.Enqueue( $_.FullName ) | Out-Null
                $ToRemoveCount += 1
            } else {
                Write-Debug "  Don't Expire: $relFile"
            }
        }
    }
    Write-Host ("Found {0} obsolete files from a collection of {1} remote files." -f `
        $ToRemoveCount, $RemoteFileList.Count )
    $removed = 0
    while ($ToRemove.Count -ne 0) {
        $oneFile = $ToRemove.Dequeue()
        try {
            Remove-Item $oneFile
            Write-Debug "   Deleted $oneFile"
            $removed += 1
        } catch {
            Write-Warning ("Could not delete the local file ${oneFile}: {0}" -f $_.ToString())
        }
    }
    return $removed
}

$__Timing_active = New-Object System.Collections.Hashtable
$__Timing_records = New-Object System.Collections.HashTable
$__Timing_sequence = 1

Function Start-Timer([string]$Tag) {
    $__Timing_active[$Tag] = Get-Date
}
Function Stop-Timer([string]$Tag,[string]$Description="") {
    $now = Get-Date
    if ($__Timing_active.ContainsKey($Tag)) {
        $delta = $now - $__Timing_active[$Tag]
        $newTag = $Tag + "-" + $__Timing_sequence.ToString("D6")
        $__Timing_sequence += 1
        $__Timing_records[$newTag]=$delta
        Write-Debug ("Timing tag $newTag took {0} milliseconds ({1} seconds): $Description" -f $delta.TotalMilliseconds,$delta.TotalSeconds)
        return $delta
    } else {
        Write-Warning "Timing for tag $Tag ignored since it was never started."
    }
}


Function Check-IsAdministrator() {
<#
.Synopsis
Check-IsAdministrator returns $True if the user has likely started the shell as 
an administator.  $False if not

.Description
Using the "whoami" program in windows, the privileges are searched and $True is
returned if the SeSecurityPrivilege has been granted to the user

.Notes
  Author: Charlie Todd <zerolagtime@gmail.com>
  License: LGPL
  Copyright: (C) 2016 by Charlie Todd
#>
    $privs = whoami /priv /fo csv | ConvertFrom-Csv
    $secpriv = $privs | where-object {$_.'Privilege Name' -eq "SeSecurityPrivilege"}
    if ($secpriv) { $True } else { $False }
}

Function Install-RedHatEntitlementCACert {
<#
.Synopsis
If not already installed, load the entitlement CA for Red Hat's patch repo into the certificate store

.Description
Only use this if a Red Hat repository is being mirrored, and be aware that the certificate may
have expired.  Get the current root CA from https://cdn.redhat.com.  If the certificate is already 
installed, or if it is successfully installed, return $True, otherwise $False is returned.
Consider this certificate to be "pinned," which also avoids man-in-the-middle attacks.
#>
    $localCACert = join-path $PSScriptRoot "cdnredhatcom.crt"
    if ( (Test-Path $localCACert) -eq $true) {
        $CACert = get-content $localCACert
    } else {
        # updated 2-Jul-2017
$CACert = @"
-----BEGIN CERTIFICATE-----
MIIE9TCCAt2gAwIBAgICAMEwDQYJKoZIhvcNAQEFBQAwgbExCzAJBgNVBAYTAlVT
MRcwFQYDVQQIDA5Ob3J0aCBDYXJvbGluYTEWMBQGA1UECgwNUmVkIEhhdCwgSW5j
LjEYMBYGA1UECwwPUmVkIEhhdCBOZXR3b3JrMTEwLwYDVQQDDChSZWQgSGF0IEVu
dGl0bGVtZW50IE9wZXJhdGlvbnMgQXV0aG9yaXR5MSQwIgYJKoZIhvcNAQkBFhVj
YS1zdXBwb3J0QHJlZGhhdC5jb20wHhcNMTQwNTE0MTk0ODAyWhcNMjQwNTExMTk0
ODAyWjB9MQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExEDAO
BgNVBAcTB1JhbGVpZ2gxEDAOBgNVBAoTB1JlZCBIYXQxGDAWBgNVBAsTD1JlZCBI
YXQgTmV0d29yazEXMBUGA1UEAxMOY2RuLnJlZGhhdC5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDCQjJd93Oi+kQ5p0fDbYt/BE6WlUeaRnW97/8P
lYBcyPF2/eGB2WASvKK8+qlAycvuLEUXdlJ5Bps/pdIe8biL0lKlAh8UdUiH5TVB
7s8B/IH81E/yTd6N9CE3YkxkaZJnO0cZ0Oe6OUoP3JhZZp1uYGIU2kS5kYhDjS4Z
KSl/nZdC6I0D8kd9P1TwvxlAC6qn2Z/MMKvOvJJgBOsU+cyntPgsB5y4mfSJFazd
o692dSefdWN8aaEE10A/ifgCvgPmeEZZi7/yvDX5kiXCFhYdQjAPadgiA/wDg7i8
GJXIFWVdJUlL5x2ehMjlHfUAyMBuCu9E4zpCetXV7V3/5OU7AgMBAAGjSjBIMAkG
A1UdEwQCMAAwCwYDVR0PBAQDAgXgMC4GA1UdEQQnMCWCE3N0YWdlY2RuLnJlZGhh
dC5jb22CDmNkbi5yZWRoYXQuY29tMA0GCSqGSIb3DQEBBQUAA4ICAQCSjzOree6S
uF0Tmmd8ueh1aLnyktNCPycxtvHFx5D6/IYBjCt7Iwkc+6eR6sFV+QL7S29VjpXG
WPahIUDjlDwacXSRCywbqyr+PAhOo2vksGLXvvU/hhztn37DM9kuK9ImUXY5cykU
vT3bMMH5cg1+1a9X01Oou54TeH09WVX+w96eWhN8IkqBIB9b2i3ImZXniCTU/9PQ
x1BfxzX04yumIuHxjxzbE844hxc1NtpnF9GOY+WCOHn47o9mY7BUjCkbdyLfJ84S
juXgC49ONQTvLETqdPm2SPungIeU9VhkbgzHD26/1kpQRS9SrCcW7LFwrKUEGnbF
4gCmyrwwzMEiM9t330BEN+ZEY5K7Sf4C/K9B50hKdq4cqFvfWbjWpdH+wFqR043S
vgl82rKQwyjASrwke0S9bSFmU7QKctz0H90MEXxtxbGcS/PuJ6r2Fzel484OofOm
sKqkMjd90o0odg0MVdz/QbjEJ7PUlNAscidCaX2df6ZLrW+V7Ph498A5hi7HrIiW
LAyrrsCxNd2LD1xcaEoJuHsro3xRlOByPXsLZu5U9xhkdFDQKVwwaRIwWlR87aZw
lA79azhKvD0VzPGHV7e2vExnL5Q5z8OY5c5gx3P4yxU+5IfdiS3kwWykrWAARCzz
eILSsgtr6+dJzGmWcMQkJZsEh98ph4NZ9Q==
-----END CERTIFICATE-----
"@
    }
    $tempFile = [IO.Path]::GetTempFileName()
    try {
        $CACert | Out-File -Encoding UTF8 $tempFile
        $rootCA = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($tempFile)
        remove-item $tempFile
    } catch {
        remove-item $tempFile
        return $False
    }
    if ($rootCA.GetExpirationDateString() -lt (Get-Date)) {
        Write-Error "The entitlement root CA has expired.  Please re-obtain and export it with a browser from https://cds.redhat.com."
        return $False
    }
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("root","CurrentUser")
        $store.Open("ReadOnly")
    } catch {
        return $False
    }
    $checkHash = $rootCA.GetCertHashString()
    if ( $store.Certificates | where-object -Property Thumbprint -EQ $checkHash ) {
        Write-Verbose "No need to added the root Entitlement CA as it is already in the user's store (thumbprint $checkHash)."
        $store.Close()
        return $True
    }
    # need to load the certificate then
    $store.Close()
    try {
        Write-Verbose "Adding root CA to the user's root store (thumbprint $checkHash)"
        $store.Open("ReadWrite")
        $store.Add($rootCA)
        $store.Close()
        return $True
    } catch {
        return $False
    }
}

#Function Report-Timers([string]$Tag="") {
#    foreach ($oneTag in ($__Timing_records.Keys | where-object {$_ -matches "$Tag-"} | sort-object ) ) {
#        $baseTag = $oneTag -replace "-(\d+)",""
#        $sequence = $Matches[1]
#    }
#}
Function Parse-PreferencesJSON($file) {
    try {
        $json = get-content $file | ConvertFrom-Json  
    } catch {
        Write-Warning "Could not parse JSON in $file - $($_.exception)"
        throw "Error processing the preferences file"
    }
    $toSubProperties = $json.global | gm | where {$_.MemberType -eq "NoteProperty" -and $_.Definition -match "%\w+%" } | select -ExpandProperty Name
    foreach ($prop in $toSubProperties) {
        $val = $json.global.$prop
        $keywords = select-string "%(\w+)%" -InputObject $val -AllMatches |% matches |% value |% { $_ -replace "%","" }
        foreach ($key in $keywords) {
            $newparam = get-childitem Env: | where Name -eq $key |% value
            $val = $val -replace "%$key%",$newparam
        }
        $json.global.$prop = $val
    }
    $json
}

Function Parse-IniFile ($file) {
    $ini = @{}

    # Create a default section if none exist in the file. Like a java prop file.
    $section = "NO_SECTION"
    $ini[$section] = @{}

    switch -regex -file $file {
        "^\[(.+)\]$" {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
        }
        "^\s*([^#].+?)\s*=\s*(.*)" {
            $name,$value = $matches[1..2]
            # skip comments that start with semicolon:
            if (!($name.StartsWith(";"))) {
                $ini[$section][$name] = $value.Trim()
            }
        }
    }
    $ini
}
Function Convert-RepoToPreferences($RepoFile, $PreferencesFile) {
    $ini = Parse-IniFile $RepoFile
}
Function Replace-DateString($str) {
    if ($str -match "%([a-zA-Z]+)%" ) {
        $m = $matches[1]
        $dt = get-date -format $m
        $str = $str -replace "%$m%",$dt
    }
    return $str;
}
# either use the specified file or copy the template from the location of this script
Main-Mirror-YumRepo -prefFile (Get-PreferencesFile $PreferencesFile)
