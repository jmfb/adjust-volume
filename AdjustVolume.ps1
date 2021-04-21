$ErrorActionPreference = "Stop"

try {
	Write-Host "[$(Get-Date)] Adding C# helper classes..."
	Add-Type (Get-Content "$PSScriptRoot\AdjustVolume.cs" -Raw)

	[AdjustVolume.Program]::Run()

	Write-Host "[$(Get-Date)] Done."
	exit 0
} catch {
	Write-Host "[$(Get-Date)] $_" -BackgroundColor Red
	Write-Host "[$(Get-Date)] Loader Exceptions:"
	$_.Exception.LoaderExceptions | ForEach { $_ | Format-List -Property * }
	exit -1
}
