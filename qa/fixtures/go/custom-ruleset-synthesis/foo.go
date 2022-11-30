package main

import (
	"golang.org/x/crypto/ssh"
)

func baz() {}

func bar() {}

func foo() error {
	var err error
	_ = ssh.InsecureIgnoreHostKey()
	if err == nil {
		return err
	}
	return nil
}
