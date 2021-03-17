package portForwardapi

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// PowerShell struct
type PowerShell struct {
	powerShell string
}

// New create new session
func New() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

func (p *PowerShell) execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return
}

var (
	// Below command will enable the HyperV module
	enableHyperVCmd    = `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`
	elevateProcessCmds = `
	$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
	# Get the security principal for the Administrator role
	$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

	# Create a new process object that starts PowerShell
	$newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
	# Specify the current script path and name as a parameter
	$newProcess.Arguments = $MyInvocation.MyCommand.Definition.Path;
	
	# Write-Host -NoNewLine $script:MyInvocation.MyCommand.Definition.Path

	# Indicate that the process should be elevated
	$newProcess.Verb = "runas";
	
	# Start the new process
	$process = [System.Diagnostics.Process]::Start($newProcess);
	
	# Exit from the current, unelevated, process
	exit	
`
	firewallcmd = `
#[Ports]
#All the ports you want to forward separated by coma
$ports=@(3000,8086);


#[Static ip]
$addr='0.0.0.0';
$ports_a = $ports -join ",";



#Remove Firewall Exception Rules
iex "Remove-NetFireWallRule -DisplayName 'WSL 2 Firewall Unlock' ";

#adding Exception Rules for inbound and outbound Rules
iex "New-NetFireWallRule -DisplayName 'WSL 2 Firewall Unlock' -Direction Outbound -LocalPort 3000 -Action Allow -Protocol TCP";
iex "New-NetFireWallRule -DisplayName 'WSL 2 Firewall Unlock' -Direction Inbound -LocalPort $ports_a -Action Allow -Protocol TCP";



for( $i = 0; $i -lt $ports.length; $i++ ){
  $port = $ports[$i];
  iex "netsh interface portproxy delete v4tov4 listenport=$port listenaddress=$addr";
  iex "netsh interface portproxy add v4tov4 listenport=$port listenaddress=$addr connectport=$port connectaddress=ubuntu1804.wsl";
}

`
)

func openFirewallandPortForward() {
	posh := New()

	// Scenario 1
	// stdOut, stdErr, err := posh.execute(elevateProcessCmds)
	// fmt.Printf("ElevateProcessCmds:\nStdOut : '%s'\nStdErr: '%s'\nErr: %s", strings.TrimSpace(stdOut), stdErr, err)
	// ========= Above working and invoke a publisher permission dialog and Admin shell ================

	// Scenario 2
	// stdOut, stdErr, err := posh.execute(enableHyperVCmd)
	// fmt.Printf("\nEnableHyperV:\nStdOut : '%s'\nStdErr: '%s'\nErr: %s", strings.TrimSpace(stdOut), stdErr, err)
	// ========= Behavior(expected one): StdErr: 'Enable-WindowsOptionalFeature : The requested operation requires elevation.

	// Scenario 3 : Both scenario 1 and 2 combined
	//enableHyperVScript := fmt.Sprintf("%s\n%s", elevateProcessCmds, enableHyperVCmd)
	//stdOut, stdErr, err := posh.execute(enableHyperVScript)
	//fmt.Printf("\nEnableHyperV:\nStdOut : '%s'\nStdErr: '%s'\nErr: %s", strings.TrimSpace(stdOut), stdErr, err)

	firewallVScript := fmt.Sprintf("%s\n", firewallcmd)
	stdOut, stdErr, err := posh.execute(firewallVScript)
	fmt.Printf("firewallVScript:\nStdOut : '%s'\nStdErr: '%s'\nErr: %s", strings.TrimSpace(stdOut), stdErr, err)

	// ========= Above suppose to open a permission dialog, on click of "yes" should
	// ========= run the hyperv enable command and once done ask for restart operation
	// ========= Actual Behavior: Only invoking the Powershell in admin mode and not running the HyperV Enable command.
}

// Video Demo of Scenario 3 - https://youtu.be/4lt1QA3h59c

// Self-sign the powershell script
// https://community.spiceworks.com/how_to/153255-windows-10-signing-a-powershell-script-with-a-self-signed-certificate
// Copy below code into powershell script says 'runAsAdmin.ps1' file and self-signed-it as mentioned above and run it.

/*
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent();
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID);
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
if (-Not ($myWindowsPrincipal.IsInRole($adminRole))) {
$newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
$newProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
$newProcess.Verb = "runas";
[System.Diagnostics.Process]::Start($newProcess);
Exit;
}
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
*/

// Set the execution policy to RemoteSigned as 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned' for above demo purpose
// by opening PowerShell in Admin mode
// From Minishift context it is being taken care from below line, and no system policy is getting changed.
// Revert above by 'Set-ExecutionPolicy -ExecutionPolicy Restricted'
// https://github.com/budhram/minishift/blob/issue-907/pkg/minishift/shell/powershell/powershell.go#L57
