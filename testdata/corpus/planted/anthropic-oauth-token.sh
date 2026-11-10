#!/usr/bin/env bash
# CI wrapper. The token came from `claude setup-token` and was pasted here to get the job green.
set -euo pipefail
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-0SPILLGUARDheOsPeVoFaV7MuFFaZ0lTMci-OvRDeiygdh1kc_tVv82npuLP71rRLJBf3MGx74lUFn1mnOLiBl7UY0KQNSU
exec claude -p "$@"
