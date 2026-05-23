Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
appPath = fso.BuildPath(scriptDir, "traffic-checker-app.ps1")
command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File """ & appPath & """"
shell.Run command, 0, False
