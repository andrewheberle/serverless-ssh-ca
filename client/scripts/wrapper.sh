#!/bin/sh
#
# This is an example wrapper script to start the snap version
# of the ssh-ca-client with a ssh-agent socket in a location
# that is accessible
#

set -e

# check SSH_AUTH_SOCK is set
if [ "${SSH_AUTH_SOCK}" = "" ]; then
        printf 'No SSH_AUTH_SOCK env var set\n'
        exit 1
fi

# check SSH_AUTH_SOCK exists and is a socket
if ! [ -S "${SSH_AUTH_SOCK}" ]; then
    printf 'Error: The file at SSH_AUTH_SOCK ("%s") was not a socket.\n' "${SSH_AUTH_SOCK}"
    exit 1
fi

AGENT_DIR="$HOME/agent"

# ensure .agent dir exists
mkdir -p "$AGENT_DIR"

# start socat to proxy agent to real socket
SOCK="$AGENT_DIR/ssh.$$"
printf 'Proxying from "%s" to "%s"...\n' "${SSH_AUTH_SOCK}" "${SOCK}"
socat UNIX-LISTEN:"${SOCK}",fork UNIX-CONNECT:"${SSH_AUTH_SOCK}" &
SOCAT_PID=$!

# function to clean up socat process at end of script
cleanup() {
    if kill -0 "$SOCAT_PID" 2>/dev/null; then
        printf 'Stopping SSH agent proxy...\n'
        kill "$SOCAT_PID"
        wait "$SOCAT_PID" 2>/dev/null
        printf 'Cleanup complete.\n'
    fi
}
trap cleanup EXIT INT TERM

# start ssh-ca-client
printf 'Starting ssh-ca-client with SSH_AUTH_SOCK="%s"...\n' "${SOCK}"
env SSH_AUTH_SOCK="$SOCK" ssh-ca-client
