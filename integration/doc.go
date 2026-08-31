// Package integration exists to hold tests that span several TokenHive
// packages at once.
//
// The individual packages are tested in isolation, and isolation is the right
// default: a unit test that fails points at one place. What isolation cannot
// catch is a seam between packages — a job hash computed one way and verified
// another, a policy decision that carries a field nothing downstream reads, a
// receipt that verifies but no longer describes the job it claims to. Those
// bugs live in the gaps, so they need a test that walks the whole path.
//
// There is no production code here on purpose.
package integration
