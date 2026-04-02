//go:build darwin
// +build darwin

package main

import "syscall"

const SO_REUSEPORT = syscall.SO_REUSEPORT
