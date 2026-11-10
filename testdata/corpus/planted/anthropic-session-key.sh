#!/usr/bin/env bash
# Pulls the usage page with the browser's session cookie, copied out of devtools.
set -euo pipefail
curl -sS https://claude.example.invalid/api/usage -H "Cookie: sessionKey=sk-ant-sid01-0SPILLGUARD_SJyaCzYR_KqkVjwhtPvJeOkdfBP9YBo9QUE3tdnuPTLng-q4LUVc70U9rwt0e_QgNWeItPE7DJd01GAkwfl"
