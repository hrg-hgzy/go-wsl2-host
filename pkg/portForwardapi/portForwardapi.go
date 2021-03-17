package portForwardapi

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func execute(args ...string) (stdOut string, stdErr string, err error) {
	ps, _ := exec.LookPath("powershell.exe")
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(ps, args...)

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

func OpenFirewallandPortForward() {
	firewallVScript := fmt.Sprintf("%s\n", firewallcmd)
	stdOut, stdErr, err := execute(firewallVScript)
	fmt.Printf("firewallVScript:\nStdOut : '%s'\nStdErr: '%s'\nErr: %s", strings.TrimSpace(stdOut), stdErr, err)
}
