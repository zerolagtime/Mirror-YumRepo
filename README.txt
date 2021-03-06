
NAME
    C:\Users\ctodd\Documents\Powershell\Mirror-YumRepo.ps1
    
SYNOPSIS
    Mirror a YUM repository without having a Linux machine, even host the mirror on IIS.
    
SYNTAX
    C:\Users\ctodd\Documents\Powershell\Mirror-YumRepo.ps1 [[-MirrorRoot] <Uri>] [[-Repository] <String>] [[-DeltaZip] <String>] [[-DaysBack] <Int32>] [[-CacheFolder] <String>] 
    [-VerifyAllChecksums] [-TrimCache] [-Offline] [-SavePreferences] [-ClearPreferences] [[-PreferencesFile] <String>] [<CommonParameters>]
    
    
DESCRIPTION
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
    

PARAMETERS
    -MirrorRoot <Uri>
        The URI of a network-accessible repository of multiple branches of repositories.
        
        Required?                    false
        Position?                    1
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -Repository <String>
        The relative path after the -MirrorRoot parameter used to identify which specific repository
        to mirror.  The local file path structure will mirror this parameter.
        
        Required?                    false
        Position?                    2
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -DeltaZip <String>
        The name of a compressed folder used to store an update to the catalog and any new
        files since the last run of this program.  The resulting ZIP file can be overlaid
        onto an existing tree structure on a disconnected system.  See -TrimCache
        for a technique on removing local files that are no longer on the mirror site.
        
        This parameter also accepts date and time parameters inside the provided file name.
        The Unix Time escape characters are braced before and after with hashtag signs.
        See the examples for potential defaults.  These automatic substitutions allow for
        a great -SavePreferences setting.
        
        Timestamp your zip files automatically by providing a format string wrapped
        in percentage signs.  The format string must be in the format expected by the
        Get-Date -Format command.  See EXAMPLES for ideas.  Save it as a preference and
        never have to set it on the command line.
        
        Required?                    false
        Position?                    3
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -DaysBack <Int32>
        After updating the catalog from the mirror site, add all files found that are
        newer than the specified number of days to the ZIP file specified with -DeltaZip.
        The -DeltaZip option must be specified.  This is good for "catching up" a secondary
        offline system that may have missed an update CD.
        
        A number between 0 (just what is new during this run) and 90 (inclusive).  Whole days
        only and it is 24 hours from the time of execution.  So a value of 1 at 3pm will pull
        all deltas that were not downloaded and, in addition, all files added to the repository
        starting at 3pm the day before.
        
        Required?                    false
        Position?                    4
        Default value                0
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -CacheFolder <String>
        
        Required?                    false
        Position?                    5
        Default value                (Get-Location)
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -VerifyAllChecksums [<SwitchParameter>]
        Using the local database, compute the checksum of all locally cached files.
        Any files which fail are deleted from the local disk. Pair with -TrimCache to clean 
        up the local disk at the same time.
        
        This parameter will not be saved with -SavePreferences.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -TrimCache [<SwitchParameter>]
        Using the local database, identify files on disk that are no longer in the catalog
        and delete them.  Provide this option for sites with Internet access to clean up
        files which have expired or were retracted.  Otherwise, old files will hang around
        even though databases don't referent them.
        
        Offline networks should also specify the -Offline parameter since
        there is no access to a remote repository.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -Offline [<SwitchParameter>]
        The location where this script is running is not going to pull from an upstream
        repository.  No updates will be requested.  This only makes sense if -TrimCache
        is also provided.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -SavePreferences [<SwitchParameter>]
        Save the MirrorDir, Repo, and DeltaZip settings to a preferences file in your %APPDIR%
        folder.  The next time you call the script, those settings will override the defaults in
        this application, which makes it nice to call quickly on a daily or weekly basis without
        having to retype the same parameters every day.  Also nice if your sysadmin doesn't let 
        you run .bat or .cmd files.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -ClearPreferences [<SwitchParameter>]
        Take the settings saved with -SavePreferences and erase them, going back to the script 
        defaults.  Call this parameter if you are debugging a problem and want to see if the 
        preferences are getting in the way.
        
        This parameter will not be saved with -SavePreferences.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -PreferencesFile <String>
        The file where preferences are saved.  Set this to either save settings into a particular
        place or to retrieve them from a group of files.  Good for mirroring repositories as a 
        collection.
        
        Required?                    false
        Position?                    6
        Default value                (Join-Path ([System.Environment]::GetFolderPath(`
                                      [System.Environment+SpecialFolder]::ApplicationData)) `
                                    "yumrepo.json")
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216). 
    
INPUTS
    
OUTPUTS
    
NOTES
    
    
        Author        : Charlie Todd <zerolagtime@gmail.com>
        Version        : 1.3 - 2016/04/30
        Copyright   : Copyright 2016 Charlie Todd
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
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Write the cache for the default mirror site to your Downloads\centos folder.  Save the ZIP file
    
    
    to your Downloads folder, but the file name might be centos7-openstack-20160403-1147.zip.
    In addition to downloading new files that aren't yet local, also grab any file updates (on the remote site)
    in the last 45 days.    
    
    PS> .\Mirror-YumRepo.ps1 -CacheFolder "${env:USERPROFILE}\Downloads\centos"  `
            -DeltaZip "${env:USERPROFILE}\Downloads\centos7-openstack-%yyyyMMdd-hhmm%.zip" -DaysBack 4
    
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\>Set up your mirror, repository on the mirror, local cache folder, and a ZIP file with pattern.
    
    
    Save the settings so that next time, you can just run the program with no extra options, like with 
    a desktop shortcut.  It also will pull updates at this time.
    
    PS> .\Mirror-YumRepo.ps1 -MirrorRoot "http://mirror.cisp.com/CentOS/7" -Repository "updates/x86_64" `
            -CacheFolder "${env:USERPROFILE}\Downloads\centos-updates" `
            -DeltaZip "${env:USERPROFILE}\Downloads\centos7-updates-%yyyyMMdd-hhmm%.zip" -SavePreferences
    
    
    
    
    
    
RELATED LINKS
    https://github.com/zerolagtime/Powershell



