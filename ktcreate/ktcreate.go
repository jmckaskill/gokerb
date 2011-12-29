package main

import (
	"bufio"
	"exp/terminal"
	"fmt"
	"github.com/jmckaskill/gokerb"
	"os"
	"strings"
	"time"
)

var buf = bufio.NewReader(os.Stdin)

func prompt(p string, echo bool) string {
	fmt.Print(p + ": ")

	if echo {
		line, isprefix, err := buf.ReadLine()

		if isprefix {
			fmt.Println("Input too long")
			os.Exit(-1)
		} else if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		return string(line)

	} else {
		line, err := terminal.ReadPassword(0)
		fmt.Println()
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		return string(line)
	}

	panic("")
}

func main() {
	user := prompt("User", true)
	realm := strings.ToUpper(prompt("Realm", true))
	pass := prompt("Password", false)

	cred := kerb.NewCredential(user, realm, pass)

	// Get the login ticket to get the version number and check the password
	if _, err := cred.GetTicket("krbtgt/"+realm, time.Now().Add(time.Hour), 0); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	filename := strings.Replace(fmt.Sprintf("%s_%s.keytab", user, realm), "/", "_", -1)
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0600)

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	if err := kerb.WriteKeytab(file, []*kerb.Credential{cred}); err != nil {
		fmt.Println(err)
		os.Remove(filename)
	}

	file.Chmod(0400)
	file.Close()
}
