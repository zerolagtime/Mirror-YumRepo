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

.Parameter Offline

    Don't update the database.  Only useful to quickly grab the last number of days updates
    when the local repository has been recently updated.

.Parameter Verbose

    This common parameter shows more about what is going on during
    the evaluate and download process. This option also shows where a particular 
    preference is set or overridden.

.LINK

    https://github.com/zerolagtime/Mirror-YumRepo
       
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
    [switch]$Offline,
    $Command
)
#Requires -Version 4
#$DebugPreference="Continue"
# this list of variables also constrains what can be set in the preferences file

end { # show the flow up front, but actually execute it last so that everything else is defined
    Set-StrictMode -Version 4.0
    $config = Parse-PreferencesJSON($PreferencesFile)
    $repositories = $config.mirrors | where enabled -eq $true | select-object -expandProperty shortName; # an array more than likely
    if ($Repository) {
        if ($Repository -in $repositories) {
            $repositories = $Repository
        } else {
            throw "No such repository $Respository - valid list is: $($repositories -join ', ')"
        }
    }
    if ($ListRepositories) { Dump-RepositoryList $config.Mirrors; return $True }
    if ($repositories.gettype().basetype -Match "Array") {$repoCount = $repositories.Count } else {$repoCount = 1} 
    $repoIdx = 0.5
    foreach ($repo in $repositories) {
        Write-Progress -id 1 -activity "Mirroring $repoCount YUM repositories" -status "Processing mirror $repo" `
            -PercentComplete ([int]($repoIdx * 100 / $repoCount)); $repoIdx++
        $mirrorConfig = $config.mirrors | where shortName -eq $repo | select -First 1
        $deltaFiles = Update-MirrorSite -GlobalConfig $config.global -MirrorConfig $mirrorConfig
        $cacheFolder = join-path $config.global.cacheRootFolder $mirrorconfig.shortName
        if (($config.global | gm -name deltasEnabled) -and $config.global.deltasEnabled) { # TODO - not defined
            try {
                Generate-DeltaZip -ZipFolder $config.global.deltaFolder -shortName $repo -Files $deltaFiles `
                        -maxBytes ($config.global.deltaMaxMegaBytes*1024*1024) -rootFolder $cacheFolder
            } catch {
                Write-Warning "Error creating a delta ZIP.  Sleeping for 10 seconds to allow more updates to be cancelled"
                Write-Verbose "Error was $($_.tostring())"
                Start-Sleep -Seconds 10
            }
        }
    }
    Write-Progress -activity "ignored" -id 1 -Completed
    if ($config.global.deltasEnabled) {
        $deltaFolder = $config.global.deltaFolder -replace "/","\"
        & explorer.exe /n,"$deltaFolder"
    }
}

Begin { # define all the helper functions first, but save them to a later part of the file
Function Dump-RepositoryList($repositories) {
    $counter=1
    ForEach ($repo in $repositories) {
        Write-Host "========== Repository #$counter =========="
        Write-Host ("    Title (short name): {0} ({1})" -f $repo.title,$repo.shortName)
        Write-Host (" Repository is enabled: {0}" -f $repo.enabled)
        if ($repo | gm -MemberType NoteProperty | where name -eq "mirrorListURI") {
            Write-Host ("  List of mirrors from: {0}" -f $repo.mirrorListURI) 
        } else {
            Write-Host ("   List of remote URIs:")
            $repo.remoteRootURIs |% { Write-Host ("       {0}" -f $_) } 
        }
        $counter++
    }
    Write-Host "========== End of Repository List =========="
}
Function Update-MirrorSite($GlobalConfig,$MirrorConfig) {
    $files=new-object System.Collections.ArrayList
    if (($mirrorConfig | gm -name MirrorListURI) -and $mirrorConfig.mirrorListURI) {
        $mirrorSite=Get-YumMirror -MirrorURI $MirrorConfig.mirrorListURI
        $mirrorConfig | Add-Member -NotePropertyName "RemoteRootURIs" -NotePropertyValue @($mirrorSite)
    } else { 
        $mirrorSite = $mirrorConfig.remoteRootURIs[0]
    }
    $cacheFolder = join-path $GlobalConfig.cacheRootFolder $mirrorConfig.shortName
    $mirrorConfig | Add-Member -NotePropertyName "WebSession" -NotePropertyValue (New-Object Microsoft.PowerShell.Commands.WebRequestSession)
    if (! $script:Offline) {
        $catalogFiles = Get-YumCatalogFiles -mirrorConfig $MirrorConfig -cacheFolder $cacheFolder
    } else {
        $catalogFiles = Get-ChildItem (join-path $cacheFolder "repodata") | select-object -ExpandProperty FullName
    }
    $catalogFiles |% {$files.Add(($_.Replace($cacheFolder,"") -replace "^\\","")) | out-null}
    $allRPMs  = Get-RPMsInCatalog  -mirrorSite (get-random @($mirrorSite)) `
        -catalogFiles ($catalogFiles  | where {$_ -match "primary\.xml\.gz"}) `
        -CacheFolder $cacheFolder
    if (!$allRPMs) {return $null} 
    $counter=0
    Write-Progress -id 18 -Activity "Checking cache to avoid re-downloads" -Status "Reading local file list" -PercentComplete 0
    $allRPMsLessCached = $allRPMS |% {
        if ($counter++ % 10 -eq 0) {
            Write-Progress -id 18 -Activity "Checking cache to avoid re-downloads" `
                -Status "$counter of $($allRPMS.count) - $($_.href)" `
                -PercentComplete ([int]($counter*100.0/$allRPMS.count))
        }
        #$item = $cachedFiles | where FullName -like "*$($_.relativePath)"
        $item = get-item $_.localPath -ErrorAction SilentlyContinue
        if (! $item) {
            $_
        } elseif ($item -and $item.length -ne $_.bytes) {
            Write-Warning "Removed partial/corrupted download of $($item.name)"
            Remove-Item $item.FullName
            $_
        } 
        # otherwise, the item is already on disk and should not be downloaded again
    }
    Write-Progress -id 18 -Activity "Checking" -Completed
    $retrievedFiles=$Null
    if ($allRPMsLessCached -and $allRPMsLessCached.count -gt 0) {
        $retrievedFiles = Get-URIsInGroups -CacheFolder $cacheFolder `
            -globalConfig $GlobalConfig -URIs $allRPMsLessCached.mirror_uri
    }
    # if no files were downloaded, then just stop now - unless we are going back in time
    if (!$retrievedFiles -and $DaysBack -eq $Null) {return $null}
    if ($DaysBack -ne $Null) { # $allRPMs is culled for just the last X days
        $allRPMsLessCached = $allRPMs
    }
    $allRPMsLessCached |% { 
        $rel = $_.localpath.replace($cachefolder,"") -replace "^\\",""
        $rel = $_.relativePath
        if ($_.localpath -in $retrievedFiles -or ( (test-path $_.localpath) -and $DaysBack -ne $Null ) ) {
            $files.Add($rel) | out-null
            Write-Verbose "Successfully retrieved $rel"
        } else {
            Write-Warning "Failed to download $rel"
        }
    }
    return $files
}

Function Get-YumCatalogFiles($cacheFolder,$mirrorConfig) {
<#
.DESCRIPTION
    For a particular mirror, get the repomd.xml file,
    download any missing catalog files, remove stale catalog files,
    and return the list of all files that would need archived
    or expanded for further analysis
#>
    $files=new-object System.Collections.ArrayList
    $catalogPath=join-path $cacheFolder "repodata"

    if ( (test-path $catalogPath) -eq $False) {
        Write-Verbose "Creating repodata folder $catalogPath"
        new-item -ItemType Container $catalogPath | out-null
    }
    $existingCatalog = get-childitem $catalogPath 

    $relpath = "repodata/repomd.xml"
    $repoMDURI=Join-Uri $mirrorConfig.RemoteRootURIs[0] $relpath
    $repoMDURI | Add-Member -MemberType Noteproperty -Name "relativePath" -Value $relpath
    Get-URIs -CacheFolder $cacheFolder -globalConfig $mirrorConfig -URIs $repoMDURI -overwrite `
        |% { $files.Add($_) | out-null }
    # $files just contains the repomd.xml file
    $mirror = get-random $mirrorConfig.RemoteRootURIs
    $catalogEntries = Get-CatalogURIs ( [xml](Get-content $files[0]) )
    $toGetFiles = $catalogEntries.href | where { $p = join-path $cachefolder $_; !(test-path -PathType Leaf $p)} 
    $toGet = $toGetFiles |% { 
        $u = Join-Uri $mirror $_  
        $u | Add-Member -MemberType Noteproperty -Name "relativePath" -Value $_
        $u
    }
    if ($toget) {
        Get-URIs -CacheFolder $cacheFolder -globalConfig $mirrorConfig -URIs $toget
    }
    $catalogEntries |% {join-path $cacheFolder $_.href} |% {$files.Add($_) | out-null}    
    return $files
}

Function Get-CatalogURIs([xml]$repoXML) {
    $objs = $repoXML.repomd.data |% {
        $props=@{}
        if ( ($_ | Get-Member size) -ne $Null ) { $size = $_.size } else {$size = 0}; # RHEL 5 file has no size attrib
        $props.href = $_.location.href
        $props.size = $size
        $props.timestamp = $_.timestamp
        $props.checksum = $_.checksum
        $props.checksumType = $_.checksum.type
        $props.type = $_.type
        $props.cached=$Null
        New-object -TypeName PScustomObject -Property $props
    }
    return $objs
}

function Get-YumMirror($MirrorURI) {
    try {
        $req = Invoke-WebRequest $MirrorURI
    } catch {
        Write-Error "Error requesting $($MirrorURI): $($_.toString())"
        throw
    }
    $mirrorList = $req.content -split "`n"
    return $mirrorList
}

Function Get-URIsInGroups($CacheFolder,$globalConfig,$URIs,[switch]$overwrite,[int]$groupSize=10) {
    # It is possible to request too many files through BITS.  We will break it into groups of $groupSize URIs
    # Fancy trickery from     
    $script:counter=0;
    $groups = $URIs | group-object -Property { [math]::Floor($script:counter++ / $groupSize) }
    $gc = 0
    if ($overwrite) {
        $destinations = $groups |%  {
            if ($groups.count -gt 1) { 
                Write-Progress -id 20 -Activity "Download $($URIs.count) files in groups" `
                    -Status "Group $($gc+1) of $($groups.count) ($groupsize files per group)" `
                    -PercentComplete ([int]($gc*100.0/$groups.count)); $gc++;
            }
            Get-URIs -CacheFolder $CacheFolder -globalConfig $globalConfig -URIs $_.group -overwrite
        }
    } else {
        $destinations = $groups |%  { 
            if ($groups.count -gt 1) { 
                Write-Progress -id 20 -Activity "Download $($URIs.count) files in groups" `
                    -Status "Group $($gc+1) of $($groups.count) ($groupsize files per group)" `
                    -PercentComplete ([int]($gc*100.0/$groups.count)); $gc++;
            }
            Get-URIs -CacheFolder $CacheFolder -globalConfig $globalConfig -URIs $_.group
        }
    }
    Write-Progress -id 20 -Activity "Download in groups" -Completed
    return $destinations
}

Function Get-URIs($CacheFolder,$globalConfig,$URIs,[switch]$overwrite) {
    # BITS will do the heavy lifting for us
    $destinations = @{}
    if ( $URIs | gm -Name "relativePath" ) { 
        $destinations = $URIs.relativePath |% { join-path $cacheFolder $_ } # mainly repomd.xml
    } else {
        $destinations = $URIs.localPath 
    }
    $folders=@{} 
    $destinations |% { 
        $p = split-path -Parent $_
        $folders.$p = $True
    } 
    $folders.Keys |% {
        if (! (Test-Path -PathType Container $_) ) {
            Write-Verbose "Making local folder $_"
            mkdir -force $_  | out-null
        }
    }
    if ($overwrite) { # mainly used to forcefully reload catalog files which are small
        $destinations |% {if (Test-Path $_) {Remove-Item -verbose $_ }}
    }
    try {
        Start-BitsTransfer -Source $URIs -Destination $destinations -TransferType Download -ErrorAction Inquire  
    } catch {
        Write-Warning "BITS failed to download files. Cause: $($_.toString()) (see https://msdn.microsoft.com/en-us/library/windows/desktop/aa362823(v=vs.85).aspx)"
        $destinations=$null
    }
    return $destinations
}

Function Get-RPMsInCatalog($catalogFiles,$mirrorSite,$CacheFolder,$DaysBack=$DaysBack) {
    $allRPMs = New-Object System.Collections.ArrayList
    $timesPast = (get-date (get-date -format "MM/dd/yyyy")).adddays(-$DaysBack); # 12:00am today - days back
    $newestRPMDate=(get-date).addyears(-4); # anything in the last four years is way too old
    foreach ($cf in $catalogFiles) {
        $expandedCF = Expand-CatalogFile -PathName $cf
        if (! $expandedCF) {
            Write-Warning "Error decompressing $cf - it is likely that no files will be found."
            return $Null
        }
        try {
            $counter=0
            $sr = New-Object System.IO.StreamReader($expandedCF) 
            $lastPreview=get-date
            while (($rpmBlock = Get-RPMBlockFromStream -streamReader $sr) -ne $Null) {
                $perc = $sr.BaseStream.Position * 100.0 / $sr.BaseStream.Length
                $PackageName = "{0} v{1} - {2}" -f $rpmBlock.package.name, $rpmBlock.package.version.ver, `
                    $(if($rpmBlock.package.summary.length -gt 30) { 
                        $rpmBlock.package.summary.substring(0,27) + "..." 
                     } else {
                        $rpmBlock.package.summary
                     })
                if ($counter++ % 10 -eq 0 -or ((get-date)-$lastPreview).totalSeconds -gt 1) {
                    Write-Progress -id 10 -Activity "Reading RPM records from $(split-path -leaf $cf)" `
                        -Status "Parsing $PackageName" -PercentComplete $perc
                }
                if($DaysBack) {
                    $fileDate = (get-date '1/1/1970 12:00am').addseconds($rpmblock.package.time.file)
                    if ( $fileDate -lt $timesPast ) {
                        continue; # skip files older than $DaysBack
                    }
                    if ($fileDate -gt $newestRPMDate) {
                        $newestRPMDate = $fileDate
                    }
                }
             $t = measure-command {
                $info = Create-FileInfo -href $rpmBlock.package.location.href -bytes $rpmBlock.package.size.package `
                                            -timestamp $rpmBlock.package.time.file -checksum $rpmBlock.package.checksum.'#text' `
                                            -checksumAlgorithm $rpmBlock.package.checksum.type -MirrorSite $mirrorSite `
                                            -relativePath $rpmBlock.package.location.href `
                                            -localPath (join-path $CacheFolder $rpmBlock.package.location.href)
            }
            #Write-Verbose "Create-FileInfo took a total of $($t.totalMilliseconds)"
               $allRPMs.Add($info) | out-null
               $lastPreview=get-date
            }
        } catch {
            Write-Warning "An error occurred while processing a catalog file.  The package list may be incomplete. $($_.tostring())"
        } Finally { 
            $sr.Close(); 
            Write-Host "Finished reading from expanded catalog file $cf."; 
        }
    }
    Write-Progress -id 10 -Activity "Reading RPM records" -Completed
    if ($allRPMs.count -eq 0) {
        Write-Warning ("No RPMS found in the last $DaysBack days. Newest RPM was published on {0} ({1} days ago)" `
            -f $newestRPMDate,[int]((get-date)-$newestRPMDate).totaldays)
    } else {
        Write-Verbose ("Newest RPM was published on {0} ({1} day(s) ago)" -f $newestRPMDate,[int]((get-date)-$newestRPMDate).totaldays)
    }
    Remove-Item $expandedCF
    return $allRPMs
}

Function Get-RPMBlockFromStream($streamReader) {
    # approach #1 - just suck in the whole XML which is likely HUGE and slow to parse
    # approach #2 - try to make a terrible, by-hand extractor of XML data
    # approach #3 - suck out just one record at a time, treat it like xml, and move on - SAX like
    # Below is approach #3, but we have to be somewhat aware of the XML structure/tags
    # with some band-aids to avoid dealing with namespaces.  Also strip out unused tags which
    # slow down XML parsing into a DOM.
    # Input variable is a StreamReader - don't want to suck in the whole file
    $xml = New-Object XML
    $packageXML=""
    $line=0; 
    $gatherLines=$False
    $NL="`n"; 
    $keepReading=$True
    $totalIORead=0;
    if (! (get-variable -scope script | where name -eq "__regexRPM" )) {       
        $script:__regexRPM = @{
            regexPackageOpen=[regex]"<package( |>)";
            regexPackageClose=[regex]"</package>";
            regexPackageOpenClose=[regex]"<[/]?package( |>)";
        }
    }
    $lines = new-object System.Collections.ArrayList
    $tt = measure-command {
    while (($s = $streamReader.ReadLine()) -ne $null) {
        if ($lines.count -gt 5000 -and $lines.count % 250 -eq 0) { 
            Write-Host "Delays in reading: Line #$($lines.count)" }
        #if ($s -match $script:__regexRPM.regexName) {  if ($matches[1] -like "kernel*") {
        #    $tick = 1 }
        #}
        if ($s -match $script:__regexRPM.regexPackageOpenClose ) {
            if ($gatherLines -eq $False) { 
                $gatherLines=$True
            } else {
                $gatherLines=$False
                $lines.Add($s) | Out-Null
                break
            }
        }
        if ($gatherLines) { 
            $lines.Add($s) | Out-Null
        }
    }
    $packageXML = $lines -join $NL
    $packageXML = $packageXML -replace "(?s)<(file)[^>]*>.*?</file>","" `
            -replace "(?s)<(rpm:requires)[^>]*>.*?</rpm:requires>","" `
            -replace "(?s)<(rpm:provides)[^>]*>.*?</rpm:provides>","" `
            -replace "(?s)<(rpm:conflicts)[^>]*>.*?</rpm:conflicts>","" `
            -replace "(?s)<(rpm:obsoletes)[^>]*>.*?</rpm:obsoletes>","" `
            -replace "(?s)<(format)[^>]*>.*?</format>","" `
            -creplace '(?m)^\s*\r?\n','' -replace "<rpm:","<rpm-" -replace "</rpm:","</rpm-"
    try {
        # rather than ensure that namespaces are imported, we doctor them
        # up to just look like normal tags.  Repeat after me: "Not evil, but faster and cleaner code"
        # since strings are easier to mangle than multiple namespace XML structures are to parse.
        # and while we're at it, delete blank lines
        $t = measure-command {
            #$packageXML = ($packageXML  -replace $script:__regexRPM.regexRPMOpen,"<rpm-" `
            #        -replace $script:__regexRPM.regexRPMClose,"</rpm-")  `
            #        -creplace '(?m)^\s*\r?\n',''; 
            $xml.LoadXml( $packageXML )}
        #Write-Verbose ("Parse Factor: {0,5}" -f [int]($t.TotalMilliseconds*1000/$packageXML.length))
        $result=$xml
        #break
    } catch {
        Write-Error "Error reading XML from a catalog file, ending at line $line"
        $result= $null
        #break
    }
    } # end of measure command
    Write-Verbose ("Read/Block factor: {0,5} ({1})" -f `
            [int]($tt.TotalMilliseconds*1000/$lines.count), $result.package.name)
    remove-variable lines
    return $result
}

# pass in pieces from an RPM XML blob as presented in the catalog file
Function Create-FileInfo() {
    Param( [string]$href, [int]$bytes=0, [int]$timestamp=0, [string]$checksum=$null, 
           [string]$checksumAlgorithm,[uri]$mirrorSite,[string]$relativePath,[string]$localPath
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
    # since we need to keep things relative in the cache
    $prop=[ordered]@{
            href=$href; bytes=$bytes; 
            timestamp=([TimeZone]::CurrentTimeZone.ToLocalTime('1/1/1970').AddSeconds($timestamp)); 
            checksum=$checksum;
            checksumAlgorithm=$checksumAlgorithm;
            mirror_uri=(Join-Uri $Mirrorsite $href);
            local_newer=$Null;
            relativePath=$relativePath;
            localPath=$localPath;
        }
    $prop.mirror_uri | Add-Member -MemberType NoteProperty -Name "relativePath" -Value $relativePath 
   if ($bytes -eq 0) { # typically only with really old catalog files - ask the website for download info
        try {
            $ProgressPreference = "silentlyContinue"
            $request = Invoke-WebRequest -Uri $prop.mirror_uri.AbsoluteUri -Method HEAD -WebSession $ScriptWebSession
            $prop.bytes = $request.Headers.'Content-Length'
            if ($timestamp -eq 0) {
                $prop.timestamp = Get-date $request.Headers.'Last-Modified'
            }
            $ProgressPreference = "Continue"
        } catch {
            $prop.bytes=0
        }
    }
    New-Object -TypeName PSObject -Prop $prop
}

Function Parse-PreferencesJSON($file) {
    if (! $file) {
        $file = join-path $PSScriptRoot "repositories.json"
        if (!(Test-Path $file)) {
            throw "Could not find configuration file $file"
        }
    }
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
            if ($newparam) {
                $val = $val -replace "%$key%",$newparam
            } else {
                try {
                    $newval = Replace-DateString -str $val
                    if ($newval -ne $val) { $val=$newval }
                } catch {
                    Write-Warning "Unrecognized substitution %$key% in $file.  Ignoring."
                }
            }
        }
        $json.global.$prop = $val
    }
    $json
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
    $rootCA = Get-HttpsPublicKeyCert -Uri "https://cdn.redhat.com" -force
    if (! $rootCA ) {
        Write-Error "Couldn't obtain the HTTPS Root Certificate for https://cdn.redhat.com.  Proxy interference?"
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

Function Expand-CatalogFile($PathName,$TempFolder=$env:TMP) {
    $DestFile = join-path $tempFolder ("yumrepo-{0}.xml" -f ([guid]::NewGuid()))
    Expand-GZip -NewName $DestFile -FullName $PathName
    if ((Test-Path $DestFile) -and (get-item $DestFile).Length -gt 0) {
        return $DestFile
    } else {
        Write-Warning "Error decompressing $PathName to $Destfile."
        start-sleep -Seconds 5
        return $null
    }
}

Function Generate-DeltaZip ([string]$ZipFolder,[string]$shortName,[string []]$Files,[int64]$maxBytes=(640*1024*1024),[string]$rootFolder) {
    # assumptions: 
    # 1. Files are not compressible - RPMs and GZ files are expected
    # 2. ZipFolder is writable
    # 3. Built-in Compress-Archive will not retain the needed directory structure
    try {Add-Type -AssemblyName System.Io.Compression.Filesystem} catch {Write-Verbose "Zip file support already loaded.  Reusing last install."}
    $rearranged = Split-FilesForZipping -cachePath $rootFolder -files $Files -maxBytes $maxBytes
    foreach ($collection in $rearranged) {
        $zipFile = Get-NextZipFile -ZipFolder $ZipFolder -shortName $shortName
        # add the $collection of files to the zipFile
        $result=New-ZipFile -FilePath $zipFile -files $collection -cacheFolder $rootFolder
    }
}

# example on run #1: C:\repos-01.zip
# example on run #2: C:\repos-02.zip
# This function has side effects and does not return the same result each time.
Function Get-NextZipFile([string]$ZipFolder,[string]$shortName) {
    if (! (get-variable -Scope Script | where Name -eq "__zipPartIndex" ) ) {
        $script:__zipPartIndex=1
    }
    $today=get-date -format "yyyyMMdd"
    $pattern = join-path $ZipFolder "$shortName-{1}-{0:D2}.zip" 
    Write-Verbose ("Checking for $shortName-{1}-{0:D2}.zip" -f $script:__zipPartIndex,$today)
    while ((test-path ($pattern -f $script:__zipPartIndex,$today)) -eq $True) {
        Write-Verbose ("Skipping over existing archive $shortName-{1}-{0:D2}.zip" -f $script:__zipPartIndex,$today)
        $script:__zipPartIndex++
    }
    return ($pattern -f $script:__zipPartIndex++,$today)
}

Function Split-FilesForZipping([string]$cachePath,[string []]$files,[int64]$maxBytes) {
    $ListofLists = new-object System.Collections.ArrayList
    $subList = new-object System.Collections.ArrayList
    $runningBytes=0;
    foreach ($f in $files) {
        $fullPath = $f
        if ($cachePath) { $fullPath = join-path $cachePath $f }
        $info = get-item $fullPath 
        $bytes = $info.length
        # 1:1 default.  1:2 (0.5) is 50% file reduction
        switch -regex ($info.Extension) {
            "\.(rpm|RPM|gz|GZ|bz2|BZ2)" { $compression = 1.0; break }
            "\.(jpg|JPG|png|PNG|mp4|MP4|m4v|M4V|avi|AVI)" { $compression = 1.0; break }
            ".*" { $compression = 0.7 }
        }
        $runningBytes += $bytes * $compression
        if ($runningBytes -gt $maxBytes) {
            $ListofLists.Add($subList) | out-null
            $subList = new-object System.Collections.ArrayList
            $runningBytes = $bytes * $compression
        } 
        $subList.Add($f) | Out-Null
    }
    $ListofLists.Add($subList) | Out-Null
    , $ListofLists; # weird Powershell behavior causes a list of 1 sublist to get unrolled
}

# Create the zip file for detla files
Function New-ZipFile([string]$FilePath,[string []]$Files,[string]$CacheFolder) {
    $openMethod = "Create"
    if ( (Test-Path -Path $FilePath -PathType Leaf) -eq $True ) {
        Write-Warning "ZipFIle $FilePath - we will add files to it"
        $openMethod = "Update"
    }
    $parentFolder = split-path -Parent $FilePath
    if ( (Test-Path -Path $parentFolder -PathType Container) -eq $False ) {
        Write-Verbose "Making folder for delta zip files: $parentFolder"
        New-Item -Path $parentFolder -Force -ItemType Directory
    }
    try {
        $ZipObj = [System.IO.Compression.ZipFile]::Open($FilePath,$openMethod)
    } catch {
        Write-Warning "Error creating ZipFile $($FilePath): $($_.tostring())"
        return $_.tostring()
    }
    foreach ($file in $Files) {
        # strip off the cache folder from the name so that the zip file has clean, relative paths
        $fullPath = join-path $CacheFolder $file
        if ( (Test-ReadAccess $fullPath) -eq $True ) {
            $result = Add-ToOpenZip -ZipObj $ZipObj -localFile $fullPath -internalFile $file
        } else {
            Write-Warning "Cannot open $file to add it to $FilePath - permission denied"
        }
    }
    $ZipObj.Dispose()
    return $True
}
 
Function Test-ReadAccess([string]$FilePath) {
    # see if the user can read a file, returning $False if they can't or $True if they can
    if ( (Test-Path $FilePath) -eq $False ) {
        return $False
    }
    $user = "{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME
    try {$acls = get-acl $FilePath } catch {return $False}
    $aclsWithRead = $acls.access | where { $_.identityreference -eq $user -and $_.AccessControlType -eq "Allow" `
            -and $_.FileSystemRights -match "(FullControl|Read.*)" }
    if ($aclsWithRead.gettype().name -eq "FileSystemAccessRule"  -or `
        $aclsWithRead.gettype().name -eq "FileSecurity" -or `
        $aclsWithRead.count -gt 0) {
        return $True
    }
    return $False
}

Function Add-ToOpenZip([System.IO.Compression.ZipArchive]$ZipObj,[string]$localFile,$internalFile) {
    $compressionType="Optimal"
    if ($InternalFile -cmatch "(.rpm$|.gz$|.bz2$|.drpm$|.srpm$|.jpg$|.png$|.avi$|.mkv$|.mp4$)" ) {
        $compressionType="NoCompression"; # system.io.compression.compressionlevel
    }
    if ( $ZipObj -ne "" ) {
        try {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ZipObj, $localFile,`
                $InternalFile,$compressionType) | Out-Null
        } catch {
            throw ("Failed to add $InternalFile to the ZIP file: {0}" -f $_.ToString())
        }
    
    } else {
        throw "Failed to add $internalFile to a Zip file because the handle to the open Zip file was lost."
    }
}

############## Generic functions included inline to keep everything in one file #############
# from stackoverflow at https://stackoverflow.com/a/22236908/3945606
function Get-HttpsPublicKeyCert
{
    [OutputType([byte[]])]
    PARAM (
        [Uri]$Uri,
        [switch]$Force
    )

    if (-Not ($uri.Scheme -eq "https"))
    {
        Write-Error "You can only get keys for https addresses"
        return
    }

    $request = [System.Net.HttpWebRequest]::Create($uri)

    try
    {
        #Make the request but ignore (dispose it) the response, since we only care about the service point
        $request.GetResponse().Dispose()
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure)
        {
            #We ignore trust failures, since we only want the certificate, and the service point is still populated at this point
        }
        else
        {
            #Let other exceptions bubble up, or write-error the exception and return from this method
            if (! $force) {
                throw
            }
        }
    }

    #The ServicePoint object should now contain the Certificate for the site.
    $servicePoint = $request.ServicePoint
    $servicePoint.Certificate
    
    #$key = $servicePoint.Certificate.GetPublicKey()
    #$key
}

Function Clean-TempFolder($prefix="yumrepos-",$suffix=".xml") {
    $c = get-childitem $env:TMP -filter "$($prefix)*$($suffix)"
    if ($c) {
        Write-Warning "Found $($c.count) stale files in $($env:TMP).  Removing them if possible."
        $c | Remove-Item -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $c |% {if (Test-Path $_.fullname) {
                Write-Warning "Failed to delete $($_.name).  May be locked for permissions are messed up."
           }
        }
        return $c.count
    }
    return 0
}

# from https://github.com/patrickhuber/Powershell/blob/master/IO/Join-Uri.ps1
function Join-Uri
{
    [CmdletBinding(DefaultParametersetName="Uri")]    
    param(
        [Parameter(ParameterSetName="Uri", Mandatory=$true, Position=0)]
        [uri]$uri, 
        [Parameter(ParameterSetName="Uri", Mandatory=$true, Position=1)]
        [string]$childPath)
    $combinedPath = [system.io.path]::Combine($uri.AbsoluteUri, $childPath)
    $combinedPath = $combinedPath.Replace('\', '/')
    return New-Object uri $combinedPath
}

Function Replace-DateString($str) {
    if ($str -match "%([a-zA-Z]+)%" ) {
        $m = $matches[1]
        $dt = get-date -format $m
        $str = $str -replace "%$m%",$dt
    }
    return $str;
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
} # end of the Begin block (define code before use, but want to see the main block up front)
