#!/bin/sh
# Runs the security regression suite: every check named TestSecurity in the
# tree, each guarding one finding of the security audit (SECURITY-AUDIT.md).
#
#   scripts/security-check.sh            all checks
#   scripts/security-check.sh headers    only checks whose name contains "headers"
#
# To add a check, append it to securityChecks in api/security_test.go (or
# pkg/auth/security_test.go for the auth package); it runs here and in CI.
set -eu
cd "$(dirname "$0")/.."
filter="^TestSecurity"
if [ "${1:-}" != "" ]; then
	filter="^TestSecurity/.*$1"
fi
exec go test ./api ./pkg/auth ./web -run "$filter" -v -count=1 "$@"
