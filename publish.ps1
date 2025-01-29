try
{
    if (-not $apiKey) {
        throw "apiKey variable not set!"
    }
	push-location McAuthz/bin/Release
	dotnet publish -c release ../../
	$package = gci *.nupkg | foreach { $pkg=@{File=$_;Version=$null}; if ($_ -match '\d+\.\d+\.\d+') { $pkg.Version=[Version]($matches[0]); $pkg } else {Write-Warning "Discarded $_ because no version number could be parsed from the filename." } } | where { $_ } | sort | select -last 1
	if (-not $package) {
		throw "Couldn't resolve most recent package!"
	}

	$packagePath = $pkg.File.FullName
	Write-host "Publish command: dotnet nuget push --api-key `$apiKey --source https://api.nuget.org/v3/index.json `"$packagePath`""
    dotnet nuget push --api-key $apiKey --source https://api.nuget.org/v3/index.json "$packagePath"
} 
finally {
    pop-location
}
