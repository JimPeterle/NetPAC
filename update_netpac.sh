#!/bin/bash

######################################
# Moved to maintenance/update_netpac.sh — use: netpac update
# Kept so that updates from NetPAC 6.x still work. Will be removed in a later version.
######################################

exec bash "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/maintenance/update_netpac.sh" "$@"
