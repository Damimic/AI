// Command kepler-web-admin generates the bcrypt hash kepler-web needs for
// KEPLER_DASHBOARD_PASSWORD_HASH.
//
// Usage: kepler-web-admin hash-password
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kepler-web-admin:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || os.Args[1] != "hash-password" {
		return fmt.Errorf("usage: kepler-web-admin hash-password")
	}

	fmt.Fprint(os.Stderr, "Dashboard password: ")
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	fmt.Println(string(hash))
	return nil
}

// readPassword reads without echoing to the terminal when stdin is a TTY,
// so the password doesn't linger in terminal scrollback.
func readPassword() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}
