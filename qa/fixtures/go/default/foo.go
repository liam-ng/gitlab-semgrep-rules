package main

import (
	"golang.org/x/crypto/ssh"
)

func foo() {
	_ = ssh.InsecureIgnoreHostKey()
}
