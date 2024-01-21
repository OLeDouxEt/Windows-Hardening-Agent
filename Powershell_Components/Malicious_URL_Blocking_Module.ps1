<#
1. Request Urls from abuse.ch
2. Urls are parsed and sanitized to confirm legitamancy
3. Write active and all urls to file once a day
4. Use urls to create 2 file wall rules containing all and active malicious urls respectively
5. If request cannot be made, the 2 files from the previous day will be used
#>

$Active_URLs_endpoint = "https://urlhaus.abuse.ch/downloads/text_online/"
$All_URLs_endpoint = "https://urlhaus.abuse.ch/downloads/text/"
$Online_URL_File = "C:\Users\Public\Documents\Online_Malicious_URLs.txt"
$All_URLS_File = "C:\Users\Public\Documents\All_Malicious_URLs.txt"

# Simple URL regex to be improved later
#$Regex_String = '(https:\/\/www\.|http:\/\/www\.|ftp:\/\/www\.|https:\/\/|http:\/\/|ftp:\/\/).*(\.[a-zA-Z0-9]{1,}$)'
$Regex_String = '^(https:\/\/www\.|http:\/\/www\.|ftp:\/\/www\.|https:\/\/|http:\/\/|ftp:\/\/).*'


Function Request-Data {
    param(
        [String]$Endpoint
    )
    $url_data = ""
    try{
        $url_data = Invoke-WebRequest -Uri $endpoint
    }catch{
        Write-Warning $_ | Select-Object *
        $url_data = 1
    }
    Return $url_data
}

<#.DESCRIPTION
Used to check if request contains urls and filters out anything else using regex
#>
Function Confirm-URLS {
    param(
        [String]$Raw_data,
        [String]$regex
    )
    $real_URLs = @()
    $urls = $raw_data.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    for($i=0;$i -lt $urls.Count; $i++){
        if($urls[$i] -match $regex){
            $real_URLs += $urls[$i]
        }
    }
    Return $real_URLs
}

<#.DESCRIPTION
Once non-URLs have been filtered out, the array of urls will be written to a file.
#>
Function Write-URL_Files {
    param(
        [String]$URL_List_File,
        [Array]$Urls
    )
    $URL_Storage_Str = ""
    $Url_file_exists = Test-Path -Path $URL_List_File -PathType leaf
    if(!$Url_file_exists){
        New-Item -Path $URL_List_File -ItemType File -Force
    }
    # Avoiding numerous write operations by creating one large string instead of looping over the array and appending each line
    # to the file.
    for($i=0;$i -lt $Urls.Count;$i++){
        $URL_Storage_Str += "$($Urls[$i])`n"
    }
    $URL_Storage_Str | Out-File -FilePath $URL_List_File -Encoding unicode -Force
}

<#.DESCRIPTION
If the urls cannot be requested, the urls can be downloaded manually and this function will be used to
read the file and create an array of urls.
#>
Function Read-URL_Files {
    param (
        [String]$URL_List_File
    )
    try{
        $file_exists = Test-Path -Path $URL_List_File
        if($file_exists){
            $File_Data = Get-Content $URL_List_File
            Return $File_Data
        }else{
            Return 1
        }
    }catch{
        Write-Warning $_ | Select-Object *
        Return 1
    }
}

<#.DESCRIPTION
Function used to create a rule to block outgoing and incoming traffic to and from the urls requested.
This will only create a rule to block urls that have been determined to still be online and active.
#>
Function Set-Online_Rule {

}

Function Set-All_Malicious_Rule {

}

$data = Request-Data -Endpoint $Active_URLs_endpoint
if($data -ne 1){
    $confirmed_URLs = Confirm-URLS -Raw_data $data -regex $Regex_String
    Write-URL_Files -URL_List_File $Online_URL_File -Urls $confirmed_URLs
}else{
    $URL_List = Read-URL_Files -URL_List_File $Online_URL_File
}