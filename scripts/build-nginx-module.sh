#!/bin/sh
# Builds ngx_http_upload_shield_module.so against an nginx source tree.
# Usage: scripts/build-nginx-module.sh NGINX_SRC [configure options of the target nginx ...]
# The module must be built from the same nginx version and with the same
# configure options as the nginx that will load it.
set -eu
[ $# -ge 1 ] || { echo "usage: $0 NGINX_SRC [configure options]" >&2; exit 2; }
here=$(cd "$(dirname "$0")/.." && pwd)
src=$1
shift
cd "$src"
if [ -x ./configure ]; then conf=./configure; else conf=./auto/configure; fi
"$conf" "$@" --add-dynamic-module="$here/nginx"
make modules
echo "built: $src/objs/ngx_http_upload_shield_module.so"
