#!/usr/bin/env bash
# Installs a cloud-stack app into the Kubernetes cluster this machine's kubectl
# talks to. An app is any repo with a cloudstack.app.yaml (docs/APPS.md): this
# script builds its image, creates its secrets, applies its manifests and checks
# its health. It needs no cloud-stack: apps carry a copy as their standalone
# installer, and deploy/app/install.sh runs it on a lab host and then registers
# the app in the inventory.
#
#   app-install.sh [options]            # in the app's checkout, or --dir DIR
#
# Options:
#   --dir DIR        the app's checkout (default: the current directory)
#   --tag TAG        image tag (default: the checkout's short commit, else "dev")
#   --image IMAGE    use this image instead of building one
#   --check          read and check the manifest and the cluster, change nothing
#   --render DIR     write the manifests as they would be applied to DIR
#   --uninstall      delete the app's namespace (its data included)
#
# Environment:
#   KUBECTL          kubectl to use (default: kubectl, else microk8s or k3s kubectl)
#   REGISTRY         push the image there (host:port[/path]) instead of loading it
#                    into the cluster's containerd
#   NODEPORT         override the manifest's service.nodePort
#   <secret env>     values for secrets the manifest takes from the environment
#
# The last line of a successful install is machine-readable:
#   APP_INSTALLED name=... namespace=... nodePort=... image=... health=...
#
# Copy of cloud-stack's deploy/app/app-install.sh (origin/main a0ec48c). Keep in
# step with cloud-stack: re-copy it from there rather than editing it here.
set -euo pipefail

dir="." tag="" image="" step=install render_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?--dir needs a directory}"; shift ;;
    --tag) tag="${2:?--tag needs a value}"; shift ;;
    --image) image="${2:?--image needs a value}"; shift ;;
    --check) step=check ;;
    --render) step=render; render_dir="${2:?--render needs a directory}"; shift ;;
    --uninstall) step=uninstall ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (-h for help)" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\n[app] %s\n' "$*"; }
die() { printf '[app] %s\n' "$*" >&2; exit 1; }

cd "$dir" || die "no directory $dir"
[ -f cloudstack.app.yaml ] || die "no cloudstack.app.yaml in $(pwd)"
command -v python3 >/dev/null || die "python3 is needed to read cloudstack.app.yaml"

# ---------------------------------------------------------------- the manifest

# Reads cloudstack.app.yaml (PyYAML when present, else a reader for the plain
# subset the format uses) and prints shell assignments, checking it on the way.
manifest_vars() {
  python3 -I - cloudstack.app.yaml <<'PY'
import json, re, shlex, sys

def mini_yaml(text):
    """Block mappings and lists, flow {..} and [..], quoted and plain scalars."""
    def scalar(s):
        s = s.strip()
        if not s: return None
        if s[0] in "\"'":
            return json.loads(s) if s[0] == '"' else s[1:-1].replace("''", "'")
        if s in ("true", "false"): return s == "true"
        if s in ("null", "~"): return None
        if re.fullmatch(r"-?\d+", s): return int(s)
        if s[0] in "[{": return flow(s)
        return s
    def flow(s):
        s = s.strip()
        if s[0] == "[":
            return [scalar(x) for x in split(s[1:-1]) if x.strip()]
        out = {}
        for item in split(s[1:-1]):
            if item.strip():
                k, _, v = item.partition(":")
                out[k.strip()] = scalar(v)
        return out
    def split(s):
        parts, depth, cur, q = [], 0, "", None
        for c in s:
            if q:
                cur += c
                if c == q: q = None
                continue
            if c in "\"'": q = c
            elif c in "[{": depth += 1
            elif c in "]}": depth -= 1
            elif c == "," and depth == 0:
                parts.append(cur); cur = ""; continue
            cur += c
        parts.append(cur)
        return parts
    lines = []
    for raw in text.splitlines():
        line = re.sub(r"\s+#.*$", "", raw) if not raw.lstrip().startswith("#") else ""
        if line.strip(): lines.append((len(line) - len(line.lstrip()), line.strip()))
    def block(i, indent):
        if lines[i][1].startswith("- "):
            out = []
            while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
                body = lines[i][1][2:]
                if re.match(r"^[\w.-]+:(\s|$)", body):
                    # "- key: v" starts a mapping indented by two more
                    lines[i] = (indent + 2, body)
                    v, i = block(i, indent + 2)
                    out.append(v)
                else:
                    out.append(scalar(body)); i += 1
            return out, i
        out = {}
        while i < len(lines) and lines[i][0] == indent:
            k, _, v = lines[i][1].partition(":")
            i += 1
            if v.strip():
                out[k.strip()] = scalar(v)
            elif i < len(lines) and lines[i][0] > indent:
                out[k.strip()], i = block(i, lines[i][0])
            else:
                out[k.strip()] = None
        return out, i
    return block(0, lines[0][0])[0] if lines else {}

text = open(sys.argv[1]).read()
try:
    import yaml
    m = yaml.safe_load(text)
except ImportError:
    m = mini_yaml(text)

errs = []
def need(path, cond=True, msg=None):
    cur = m
    for p in path.split("."):
        cur = cur.get(p) if isinstance(cur, dict) else None
    if cur in (None, "") or not cond:
        errs.append(msg or f"{path} is required")
    return cur

if not isinstance(m, dict): sys.exit("cloudstack.app.yaml: not a mapping")
if m.get("apiVersion") != "cloudstack/v1" or m.get("kind") != "App":
    errs.append("apiVersion must be cloudstack/v1 and kind App")
name = need("name")
if name and not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", str(name)):
    errs.append("name must be a DNS label (lower case, digits, -)")
ns = m.get("namespace") or name
if ns and not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", str(ns)):
    errs.append("namespace must be a DNS label")
manifests = need("manifests")
wl = m.get("workload") or {}
for k in ("kind", "name", "container"):
    if not wl.get(k): errs.append(f"workload.{k} is required")
if wl.get("kind") not in (None, "Deployment", "StatefulSet", "DaemonSet"):
    errs.append("workload.kind must be Deployment, StatefulSet or DaemonSet")
svc = m.get("service") or {}
for k in ("name", "port"):
    if not svc.get(k): errs.append(f"service.{k} is required")
np = svc.get("nodePort")
if np is not None and not (isinstance(np, int) and 30000 <= np <= 32767):
    errs.append("service.nodePort must be 30000-32767")
build = m.get("build") or {}
if not build and not m.get("image"):
    errs.append("give build (to build the image) or image (to pull one)")
if build and not build.get("image"):
    errs.append("build.image (the image name the manifests use) is required")

secrets = []
for s in m.get("secrets") or []:
    if not s.get("name"): errs.append("each secret needs a name"); continue
    for k in s.get("keys") or []:
        if not k.get("key"): errs.append(f"secret {s['name']}: each key needs a key"); continue
        how = "generate" if k.get("generate") else "env" if k.get("env") else None
        if not how: errs.append(f"secret {s['name']} key {k['key']}: give generate (hex32...) or env")
        gen = str(k.get("generate") or "")
        if how == "generate" and not re.fullmatch(r"hex\d{1,3}", gen):
            errs.append(f"secret {s['name']} key {k['key']}: generate must be hexN (N bytes)")
        secrets.append("|".join([s["name"], k["key"], how or "", gen[3:] if how == "generate" else str(k.get("env")),
                                 "optional" if k.get("optional") else "required"]))

if errs:
    sys.exit("cloudstack.app.yaml:\n  " + "\n  ".join(errs))

out = {
    "APP_NAME": name, "APP_TITLE": m.get("title") or name, "APP_NS": ns,
    "APP_MANIFESTS": manifests, "APP_WL_KIND": wl.get("kind"), "APP_WL_NAME": wl.get("name"),
    "APP_WL_CONTAINER": wl.get("container"), "APP_SVC": svc.get("name"), "APP_PORT": svc.get("port"),
    "APP_NODEPORT": np or "", "APP_HEALTH": m.get("health") or "/", "APP_UI": m.get("ui") or "",
    "APP_BUILD_IMAGE": build.get("image") or "", "APP_DOCKERFILE": build.get("dockerfile") or "Dockerfile",
    "APP_CONTEXT": build.get("context") or ".", "APP_PULL_IMAGE": m.get("image") or "",
    "APP_SECRETS": " ".join(secrets),
}
for k, v in out.items():
    print(f"{k}={shlex.quote(str(v))}")
PY
}

vars="$(manifest_vars)" || exit 1
eval "$vars"
NODEPORT="${NODEPORT:-$APP_NODEPORT}"
wl_kind="$(printf %s "$APP_WL_KIND" | tr '[:upper:]' '[:lower:]')"   # bash 3 (macOS) has no ${x,,}
[ -e "$APP_MANIFESTS" ] || die "manifests: no $APP_MANIFESTS in $(pwd)"

# ---------------------------------------------------------------- the cluster

# kubectl, and how images reach the cluster's runtime
if [ -n "${KUBECTL:-}" ]; then
  read -r -a K <<<"$KUBECTL"
elif command -v kubectl >/dev/null 2>&1; then K=(kubectl)
elif command -v microk8s >/dev/null 2>&1; then K=(microk8s kubectl)
elif command -v k3s >/dev/null 2>&1; then K=(k3s kubectl)
else die "no kubectl (set KUBECTL)"
fi
k() { "${K[@]}" "$@"; }

# Where a locally built image goes when there is no REGISTRY
import_image() {
  local img="$1" sock=/var/snap/microk8s/common/run/containerd.sock
  if [ -S "$sock" ] && command -v ctr >/dev/null 2>&1 && [ -w "$sock" ]; then
    docker save "$img" | ctr -a "$sock" -n k8s.io images import - >/dev/null
  elif command -v microk8s >/dev/null 2>&1; then
    docker save "$img" | microk8s ctr image import - >/dev/null
  elif command -v k3s >/dev/null 2>&1; then
    docker save "$img" | sudo k3s ctr images import - >/dev/null
  else
    # Docker Desktop, Rancher Desktop (dockerd), kind with a shared daemon: the cluster sees Docker's images
    echo "  using Docker's image store directly"
  fi
}

if [ "$step" = uninstall ]; then
  say "deleting namespace $APP_NS (everything $APP_NAME stored in it)"
  k delete namespace "$APP_NS" --ignore-not-found --wait=true >/dev/null
  echo "  namespace $APP_NS deleted"
  exit 0
fi

# ---------------------------------------------------------------- render

# The app's manifests as they will be applied: a generated kustomization sets the
# image, the NodePort and (for an image loaded into containerd) the pull policy.
render() {
  local out="$1" img="$2" policy="$3"
  rm -rf "$out"; mkdir -p "$out/m"
  if [ -d "$APP_MANIFESTS" ]; then
    find "$APP_MANIFESTS" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) | sort | while read -r f; do cp "$f" "$out/m/"; done
  else
    cp "$APP_MANIFESTS" "$out/m/"
  fi
  [ -n "$(ls "$out/m")" ] || die "no YAML files in $APP_MANIFESTS"
  APP_BUILD_IMAGE="$APP_BUILD_IMAGE" APP_PULL_IMAGE="$APP_PULL_IMAGE" NODEPORT="$NODEPORT" APP_SVC="$APP_SVC" \
  APP_NS="$APP_NS" APP_PORT="$APP_PORT" APP_WL_KIND="$APP_WL_KIND" APP_WL_NAME="$APP_WL_NAME" \
  APP_WL_CONTAINER="$APP_WL_CONTAINER" python3 -I - "$out" "$img" "$policy" <<'PY'
import os, sys
e = os.environ
out, img, policy = sys.argv[1:4]
files = sorted(f for f in os.listdir(os.path.join(out, "m")) if f.endswith((".yaml", ".yml")))
last = img.split("/")[-1]
name, tag = (img.rsplit(":", 1) if ":" in last else (img, "latest"))
src = e["APP_BUILD_IMAGE"] or e["APP_PULL_IMAGE"].rsplit(":", 1)[0]
lines = ["apiVersion: kustomize.config.k8s.io/v1beta1", "kind: Kustomization", "resources:"]
lines += [f"  - m/{f}" for f in files]
lines += ["images:", f"  - name: {src}", f"    newName: {name}", f'    newTag: "{tag}"']
patches = []
if e["NODEPORT"]:
    patches.append(f"""apiVersion: v1
kind: Service
metadata: {{name: {e['APP_SVC']}, namespace: {e['APP_NS']}}}
spec:
  type: NodePort
  ports:
    - port: {e['APP_PORT']}
      nodePort: {e['NODEPORT']}""")
if policy:
    patches.append(f"""apiVersion: apps/v1
kind: {e['APP_WL_KIND']}
metadata: {{name: {e['APP_WL_NAME']}, namespace: {e['APP_NS']}}}
spec:
  template:
    spec:
      containers:
        - name: {e['APP_WL_CONTAINER']}
          imagePullPolicy: {policy}""")
if patches:
    lines.append("patches:")
    for i, p in enumerate(patches):
        fn = f"patch-{i}.yaml"
        with open(os.path.join(out, fn), "w") as fh:
            fh.write(p + "\n")
        lines.append(f"  - path: {fn}")
with open(os.path.join(out, "kustomization.yaml"), "w") as fh:
    fh.write("\n".join(lines) + "\n")
PY
  k kustomize "$out" > "$out/rendered.yaml" || die "kustomize failed on $APP_MANIFESTS"
  grep -q "namespace: $APP_NS" "$out/rendered.yaml" || die "the manifests don't use namespace $APP_NS (cloudstack.app.yaml namespace)"
}

if [ -z "$tag" ]; then tag="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"; fi
if [ -n "$image" ]; then :
elif [ -n "$APP_PULL_IMAGE" ] && [ -z "$APP_BUILD_IMAGE" ]; then image="$APP_PULL_IMAGE"
elif [ -n "${REGISTRY:-}" ]; then image="${REGISTRY%/}/$APP_BUILD_IMAGE:$tag"
else image="$APP_BUILD_IMAGE:$tag"
fi
# An image only containerd has must not be pulled
policy=""; if [ -z "${REGISTRY:-}" ] && [ -n "$APP_BUILD_IMAGE" ] && [ "$image" = "$APP_BUILD_IMAGE:$tag" ]; then policy=IfNotPresent; fi

if [ "$step" = render ]; then
  render "$render_dir" "$image" "$policy"
  echo "[app] rendered $APP_NAME ($image) to $render_dir/rendered.yaml"
  exit 0
fi

say "$APP_TITLE: namespace $APP_NS, $wl_kind $APP_WL_NAME, image $image"
k version --request-timeout=10s >/dev/null 2>&1 || die "the cluster isn't reachable with ${K[*]}"
if [ -n "$NODEPORT" ]; then
  owner="$(k get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{.spec.ports[*].nodePort}{"\n"}{end}' |
    awk -v np="$NODEPORT" '{for (i=2;i<=NF;i++) if ($i==np) print $1}' | grep -v "^$APP_NS/" | head -1 || true)"
  [ -z "$owner" ] || die "NodePort $NODEPORT is taken by $owner (set NODEPORT)"
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
render "$tmp/r" "$image" "$policy"
if [ "$step" = check ]; then
  echo "  ok   cloudstack.app.yaml, the manifests ($(grep -c '^kind:' "$tmp/r/rendered.yaml") objects) and the cluster"
  exit 0
fi

# ---------------------------------------------------------------- build

if [ -n "$APP_BUILD_IMAGE" ] && [ "$image" != "$APP_PULL_IMAGE" ] && [ -z "${SKIP_BUILD:-}" ]; then
  command -v docker >/dev/null || die "docker is needed to build $APP_BUILD_IMAGE"
  say "building $image"
  docker build -q -t "$image" -f "$APP_DOCKERFILE" "$APP_CONTEXT" >/dev/null || die "docker build failed"
  if [ -n "${REGISTRY:-}" ]; then
    docker push -q "$image" >/dev/null || die "docker push to $REGISTRY failed"
  else
    import_image "$image"
  fi
fi

# ---------------------------------------------------------------- secrets

k create namespace "$APP_NS" --dry-run=client -o yaml | k apply -f - >/dev/null
for spec in $APP_SECRETS; do
  IFS='|' read -r sname skey how arg need <<<"$spec"
  have="$(k -n "$APP_NS" get secret "$sname" -o jsonpath="{.data.${skey//./\\.}}" 2>/dev/null || true)"
  [ -z "$have" ] || continue
  if [ "$how" = generate ]; then
    value="$(openssl rand -hex "$arg")"
  else
    value="${!arg:-}"
    if [ -z "$value" ]; then
      [ "$need" = optional ] && continue
      die "secret $sname needs $skey: set $arg (it is read once and stored in the cluster)"
    fi
  fi
  ( umask 077
    printf '{"data":{"%s":"%s"}}' "$skey" "$(printf %s "$value" | base64 | tr -d '\n')" > "$tmp/patch.json" )
  if k -n "$APP_NS" get secret "$sname" >/dev/null 2>&1; then
    k -n "$APP_NS" patch secret "$sname" --type merge --patch-file "$tmp/patch.json" >/dev/null
  else
    k -n "$APP_NS" create secret generic "$sname" >/dev/null
    k -n "$APP_NS" patch secret "$sname" --type merge --patch-file "$tmp/patch.json" >/dev/null
  fi
  rm -f "$tmp/patch.json"
  echo "  secret $sname: added $skey ($how)"
done

# ---------------------------------------------------------------- apply

say "applying $(grep -c '^kind:' "$tmp/r/rendered.yaml") objects"
k apply -f "$tmp/r/rendered.yaml" >/dev/null
k -n "$APP_NS" rollout status "$wl_kind/$APP_WL_NAME" --timeout=10m >/dev/null ||
  die "$APP_WL_NAME didn't roll out (${K[*]} -n $APP_NS describe $wl_kind/$APP_WL_NAME)"
np="$(k -n "$APP_NS" get svc "$APP_SVC" -o jsonpath="{.spec.ports[?(@.port==$APP_PORT)].nodePort}" 2>/dev/null || true)"

ok=""
if [ -n "$np" ] && command -v curl >/dev/null; then
  for _ in $(seq 1 30); do
    code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$np$APP_HEALTH" || true)"
    if [ -n "$code" ] && [ "$code" != 000 ] && [ "$code" -lt 500 ]; then ok="HTTP $code"; break; fi
    sleep 2
  done
  [ -n "$ok" ] || die "no answer from http://127.0.0.1:$np$APP_HEALTH (${K[*]} -n $APP_NS logs $wl_kind/$APP_WL_NAME)"
  echo "  health http://127.0.0.1:$np$APP_HEALTH: $ok"
fi

say "$APP_TITLE is installed in namespace $APP_NS${np:+, NodePort $np}"
echo "APP_INSTALLED name=$APP_NAME namespace=$APP_NS nodePort=${np:-} image=$image health=$APP_HEALTH ui=$APP_UI"
