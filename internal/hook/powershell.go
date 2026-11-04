package hook

import "errors"

// A PowerShell call is read as text and no further.
//
// On a Windows machine with no Git Bash the model's shell is the PowerShell
// tool rather than Bash, and that tool can open any file: driven 2026-11-04 on
// Claude Code 2.1.290 on windows-latest, `Get-Content planted.txt` returned the
// planted key to the model. The command string is scanned the way a Bash command
// is. Its file operands are not, because internal/bash cannot segment PowerShell
// and internal/readers has no table for it, so which files a command reads is a
// question this cannot answer.
//
// Every call therefore records, including one that names no file. Telling those
// apart is the table this does not have, and getting it wrong in the quiet
// direction is a file read with no record anywhere, so the coverage log takes
// the noise. It lands only on the machines this tool runs on.
var errPowerShellOperands = errors.New("which files this PowerShell command " +
	"opens cannot be determined here")

// powershellTargets is the command string, with the gap beside it. scanCall
// scans what comes back and a match there blocks; otherwise the call defers.
func powershellTargets(command string) ([]target, error) {
	return []target{text(commandLabel, []byte(command))}, errPowerShellOperands
}
