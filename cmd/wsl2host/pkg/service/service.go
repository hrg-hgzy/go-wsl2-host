package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/shayne/go-wsl2-host/internal/wsl2hosts"
	"golang.org/x/sys/windows/svc/debug"

	"github.com/shayne/go-wsl2-host/pkg/hostsapi"

	"github.com/shayne/go-wsl2-host/pkg/portForwardapi"
	"github.com/shayne/go-wsl2-host/pkg/wslapi"
)

/*ugly powershell code*/

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
/* end ugly powershell code*/
const tld = ".wsl"

var hostnamereg, _ = regexp.Compile("[^A-Za-z0-9]+")

func distroNameToHostname(distroname string) string {
	// Ubuntu-18.04
	// => ubuntu1804.wsl
	hostname := strings.ToLower(distroname)
	hostname = hostnamereg.ReplaceAllString(hostname, "")
	return hostname + tld
}

// Run main entry point to service logic
func Run(elog debug.Log) error {
	infos, err := wslapi.GetAllInfo()
	if err != nil {
		elog.Error(1, fmt.Sprintf("failed to get infos: %v", err))
		return fmt.Errorf("failed to get infos: %w", err)
	}

	hapi, err := hostsapi.CreateAPI("wsl2-host") // filtere only managed host entries
	if err != nil {
		elog.Error(1, fmt.Sprintf("failed to create hosts api: %v", err))
		return fmt.Errorf("failed to create hosts api: %w", err)
	}

	updated := false
	hostentries := hapi.Entries()

	for _, i := range infos {
		hostname := distroNameToHostname(i.Name)
		// remove stopped distros
		if i.Running == false {
			err := hapi.RemoveEntry(hostname)
			if err == nil {
				updated = true
			}
			continue
		}

		// update IPs of running distros
		var ip string
		if i.Version == 1 {
			ip = "127.0.0.1"
		} else {
			ip, err = wslapi.GetIP(i.Name)
			if err != nil {
				elog.Info(1, fmt.Sprintf("failed to get IP for distro %q: %v", i.Name, err))
				continue
			}
		}
		if he, exists := hostentries[hostname]; exists {
			if he.IP != ip {
				updated = true
				he.IP = ip
			}
		} else {
			// add running distros not present
			err := hapi.AddEntry(&hostsapi.HostEntry{
				Hostname: hostname,
				IP:       ip,
				Comment:  wsl2hosts.DefaultComment(),
			})
			if err == nil {
				updated = true
			}
		}
	}

	// process aliases
	defdistro, _ := wslapi.GetDefaultDistro()
	if err != nil {
		elog.Error(1, fmt.Sprintf("GetDefaultDistro failed: %v", err))
		return fmt.Errorf("GetDefaultDistro failed: %w", err)
	}
	var aliasmap = make(map[string]interface{})
	defdistroip, _ := wslapi.GetIP(defdistro.Name)
	if defdistro.Running {
		aliases, err := wslapi.GetHostAliases()
		if err == nil {
			for _, a := range aliases {
				aliasmap[a] = nil
			}
		}
	}
	// update entries after distro processing
	hostentries = hapi.Entries()
	for _, he := range hostentries {
		if !wsl2hosts.IsAlias(he.Comment) {
			continue
		}
		// update IP for aliases when running and if it exists in aliasmap
		if _, ok := aliasmap[he.Hostname]; ok && defdistro.Running {
			if he.IP != defdistroip {
				updated = true
				he.IP = defdistroip
			}
		} else { // remove entry when not running or not in aliasmap
			err := hapi.RemoveEntry(he.Hostname)
			if err == nil {
				updated = true
			}
		}
	}

	for hostname := range aliasmap {
		// add new aliases
		if _, ok := hostentries[hostname]; !ok && defdistro.Running {
			err := hapi.AddEntry(&hostsapi.HostEntry{
				IP:       defdistroip,
				Hostname: hostname,
				Comment:  wsl2hosts.DistroComment(defdistro.Name),
			})
			if err == nil {
				updated = true
			}
		}
	}

	if updated {
		err = hapi.Write()
		if err != nil {
			elog.Error(1, fmt.Sprintf("failed to write hosts file: %v", err))
			return fmt.Errorf("failed to write hosts file: %w", err)
		}
		portForwardapi.OpenFirewallandPortForward()
	}

	return nil
}
