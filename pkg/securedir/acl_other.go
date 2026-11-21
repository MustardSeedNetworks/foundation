// SPDX-License-Identifier: BUSL-1.1

//go:build unix && !darwin && !linux

package securedir

// Other unixes: ACLs are not examined, only mode bits. macOS and Linux are the
// supported targets and have their own implementations.

func checkACL(int, string, bool, bool) error { return nil }

func stripACL(int) error { return nil }
