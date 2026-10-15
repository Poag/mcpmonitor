#!/bin/bash
# Unraid notification agent: forwards Unraid notifications to mcpmonitor.
#
# Install: copy to /boot/config/plugins/dynamix/notifications/agents/mcpmonitor.sh, chmod +x, then enable it
# under Settings > Notifications. Set URL and TOKEN below (the token is stored in plain text on the flash
# drive: use a token that only works for /ingest/unraid, i.e. MCPM_INGEST_TOKEN).
#
# Unraid runs agent scripts with the notification passed as environment variables. The names used here (EVENT,
# SUBJECT, DESCRIPTION, IMPORTANCE, CONTENT, LINK, TIMESTAMP) are from memory of Unraid's bundled agents and
# are unverified: compare with an existing agent in the same folder (for example the Discord one) and adjust.
# Unset variables are simply sent empty; mcpmonitor treats every field as optional.

URL="http://mcpmonitor.lan:8765/ingest/unraid"
TOKEN="CHANGE_ME"

# Escape a string for inclusion in a JSON string literal.
esc() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r//g' | awk 'BEGIN{ORS="\\n"} {print}' | sed 's/\\n$//'
}

BODY=$(printf '{"host":"%s","event":"%s","subject":"%s","description":"%s","importance":"%s","content":"%s","link":"%s","timestamp":"%s"}' \
  "$(esc "${HOSTNAME:-$(hostname)}")" "$(esc "$EVENT")" "$(esc "$SUBJECT")" "$(esc "$DESCRIPTION")" \
  "$(esc "$IMPORTANCE")" "$(esc "$CONTENT")" "$(esc "$LINK")" "$(esc "$TIMESTAMP")")

# Short timeout and ignore failures: a down mcpmonitor must never block or break Unraid's own notifications.
curl -fsS --max-time 5 -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data-binary "$BODY" >/dev/null 2>&1 || true
exit 0
