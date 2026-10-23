$ErrorActionPreference = "SilentlyContinue"

foreach ($port in @(8000, 8765)) {
    Get-NetTCPConnection -LocalPort $port -State Listen |
        Select-Object -ExpandProperty OwningProcess -Unique |
        ForEach-Object {
            Stop-Process -Id $_ -Force
        }
}
