//go:build linux
// +build linux

package main

import "golang.org/x/sys/unix"

const SO_REUSEPORT = unix.SO_REUSEPORT
