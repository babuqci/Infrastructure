#!/bin/bash
# Read-only TLS certificate probe, run on Linux VMs through Azure Run Command by
# `qci-infra cert-check`. Reads the public metadata of certificate files (Let's Encrypt
# live certs, acme.sh certs, and the ssl_certificate / SSLCertificateFile of nginx and
# Apache; never private keys), the certbot timers and the last renewal result, renewal
# cron entries, and which web servers run. Creates, changes and deletes nothing.
# Output: one tab-separated record per line (Run Command keeps only ~4 KB):
#   host  NAME
#   c     PATH  SHA1  NOT_AFTER_UTC  DNS_NAMES(comma)  ISSUER_CN  SOURCE(le|acme|nginx|apache)
#   tm    UNIT  LOAD  UNIT_FILE_STATE  ACTIVE  LAST_UTC  NEXT_UTC
#   sr    UNIT  RESULT  EXIT_STATUS  EXIT_UTC
#   cr    CRON_FILE
#   ws    SERVICE  STATE
#   l4    PROCESS listening on :443
#   gap   MESSAGE
export LC_ALL=C
printf 'host\t%s\n' "$(hostname)"

utc() { [ -n "$1" ] && [ "$1" != "n/a" ] && date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; }

declare -A seen
cert() { # path source
  local f=$1 real out end fp names iss
  [ -e "$f" ] || [ "$2" = le ] || return  # unused nginx/apache snippets often name absent files (snakeoil)
  [ -f "$f" ] && [ -r "$f" ] || { printf 'gap\tcannot read %s\n' "$f"; return; }
  real=$(readlink -f "$f"); [ -n "${seen[$real]}" ] && return; seen[$real]=1
  out=$(openssl x509 -in "$f" -noout -enddate -fingerprint -sha1 -issuer -text 2>/dev/null) ||
    { printf 'gap\tnot a certificate: %s\n' "$f"; return; }
  end=$(utc "$(sed -n 's/^notAfter=//p' <<<"$out")")
  fp=$(sed -n 's/^SHA1 Fingerprint=//p; s/^sha1 Fingerprint=//p' <<<"$out" | tr -d ':')
  iss=$(sed -n 's/^issuer=.*CN *= *\([^,/]*\).*/\1/p' <<<"$out" | head -1)
  names=$(grep -o 'DNS:[^,[:space:]]*' <<<"$out" | sed 's/^DNS://' | head -8 | paste -sd, -)
  printf 'c\t%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$fp" "$end" "$names" "$iss" "$2"
}

command -v openssl >/dev/null || printf 'gap\topenssl not installed\n'
for f in /etc/letsencrypt/live/*/cert.pem; do [ -e "$f" ] && cert "$f" le; done
for d in /root/.acme.sh /home/*/.acme.sh; do
  for f in "$d"/*/*.cer; do
    case "$f" in */ca.cer|*/fullchain.cer) continue ;; esac
    [ -e "$f" ] && cert "$f" acme
  done
done
if [ -d /etc/nginx ]; then
  while read -r f; do cert "$f" nginx; done < <(grep -rhoE '^[[:space:]]*ssl_certificate[[:space:]]+[^;$]+' /etc/nginx \
    2>/dev/null | awk '{print $2}' | tr -d '"'"'" | sort -u)
fi
for d in /etc/apache2 /etc/httpd; do
  [ -d "$d" ] || continue
  while read -r f; do cert "$f" apache; done < <(grep -rhoiE '^[[:space:]]*SSLCertificateFile[[:space:]]+[^[:space:]]+' \
    "$d" 2>/dev/null | awk '{print $2}' | tr -d '"' | sort -u)
done

if command -v systemctl >/dev/null; then
  for t in certbot.timer snap.certbot.renew.timer; do
    load=$(systemctl show "$t" -p LoadState --value 2>/dev/null)
    [ "$load" = "loaded" ] || continue
    printf 'tm\t%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$load" "$(systemctl show "$t" -p UnitFileState --value)" \
      "$(systemctl show "$t" -p ActiveState --value)" "$(utc "$(systemctl show "$t" -p LastTriggerUSec --value)")" \
      "$(utc "$(systemctl show "$t" -p NextElapseUSecRealtime --value)")"
    s=${t%.timer}.service
    printf 'sr\t%s\t%s\t%s\t%s\n' "$s" "$(systemctl show "$s" -p Result --value)" \
      "$(systemctl show "$s" -p ExecMainStatus --value)" "$(utc "$(systemctl show "$s" -p ExecMainExitTimestamp --value)")"
  done
  for s in nginx apache2 httpd caddy haproxy traefik; do
    st=$(systemctl is-active "$s" 2>/dev/null)
    if [ "$st" = "active" ] || [ "$st" = "failed" ]; then printf 'ws\t%s\t%s\n' "$s" "$st"; fi
  done
fi
grep -lsE 'certbot|acme\.sh|letsencrypt' /etc/crontab /etc/cron.d/* /etc/cron.daily/* /var/spool/cron/crontabs/* \
  /var/spool/cron/* 2>/dev/null | sed 's/^/cr\t/'
command -v ss >/dev/null && ss -ltnpH 'sport = :443' 2>/dev/null | grep -o 'users:(("[^"]*"' | cut -d'"' -f2 | sort -u |
  sed 's/^/l4\t/'
exit 0
