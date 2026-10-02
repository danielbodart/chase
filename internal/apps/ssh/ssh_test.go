package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	sshkey "golang.org/x/crypto/ssh"
	"pgregory.net/rapid"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
)

// catalogue is the repository's own, as the module puts it in the store.
const catalogue = "../../../apps/ssh/operations.json"

// hostKey is a fresh ed25519 key as known_hosts writes one, less the host.
func hostKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := sshkey.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(sshkey.MarshalAuthorizedKey(k))) + " " + comment
}

// defaultEnv is apps.ssh.env's default: names that change neither which
// program runs nor what code is in it.
var defaultEnv = []string{"LANG", "LC_*", "TZ", "COLUMNS", "LINES", "NO_COLOR", "SYSTEMD_COLORS"}

// config is apps/ssh.nix's for a tier answering as the tiers' defaults
// do: writes asked, guarded refused, unmatched asked, and the default env.
func config() Config {
	return Config{
		Tiers:     map[string]Tier{"trusted": {Writes: "ask", Guarded: "refuse", Unmatched: "ask", Env: defaultEnv}},
		Catalogue: catalogue,
		Agent:     "/run/user/1000/gcr/ssh",
	}
}

func prepare(t *testing.T, c Config, tier, binding string) (apps.Patch, string, error) {
	t.Helper()
	var stderr bytes.Buffer
	p, err := (&App{Config: c, Stderr: &stderr}).Prepare(context.Background(), apps.Request{
		Tier: tier, Workspace: "/w", Binding: json.RawMessage(binding),
	})
	return p, stderr.String(), err
}

// binding is one machine, server, with what else is given of it.
func binding(t *testing.T, extra string) string {
	t.Helper()
	h := map[string]any{"address": "192.168.1.10", "user": "ops", "hostKeys": []string{hostKey(t, "server")}}
	if extra != "" {
		if err := json.Unmarshal([]byte(extra), &h); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.Marshal(map[string]any{"hosts": map[string]any{"server": h}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func route(t *testing.T, c Config, extra string) policy.SSHRoute {
	t.Helper()
	p, _, err := prepare(t, c, "trusted", binding(t, extra))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SSH) != 1 {
		t.Fatalf("not one route: %+v", p.SSH)
	}
	return p.SSH[0]
}

// requireFrisket is the variable that makes a missing frisket a failure
// rather than a skip, as the flake's checks and its dev shell set it.
const requireFrisket = "CHASE_REQUIRE_FRISKET"

// frisketBin is frisket on PATH, or the test skipped without it.
func frisketBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("frisket")
	if err != nil {
		if os.Getenv(requireFrisket) != "" {
			t.Fatalf("frisket is not on PATH, and %s is set: %v", requireFrisket, err)
		}
		t.Skipf("frisket is not on PATH, so what it does is not checked; set %s to fail instead", requireFrisket)
	}
	return bin
}

// document is a policy document of these SSH routes, written to a file.
func document(t *testing.T, routes []policy.SSHRoute) string {
	t.Helper()
	b, err := json.Marshal(policy.Document{Name: "trusted", Policy: policy.Policy{Allow: []string{}, SSH: routes}})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// frisketCheck is `frisket check` of a document of these SSH routes.
func frisketCheck(t *testing.T, routes []policy.SSHRoute) (string, error) {
	t.Helper()
	bin := frisketBin(t)
	out, err := exec.Command(bin, "check", document(t, routes)).CombinedOutput()
	return string(out), err
}

// frisketDecide is frisket's own answer to each command as the route
// decides it, by `frisket check -exec`.
func frisketDecide(t *testing.T, r policy.SSHRoute, commands []string) []string {
	t.Helper()
	bin := frisketBin(t)
	f := document(t, []policy.SSHRoute{r})
	cmd := exec.Command(bin, "check", "-exec", r.Name, f)
	cmd.Stdin = strings.NewReader(strings.Join(commands, "\n") + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("frisket check -exec: %v: %s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != len(commands) {
		t.Fatalf("frisket answered %d commands of %d: %s", len(lines), len(commands), out)
	}
	answers := make([]string, len(lines))
	for i, l := range lines {
		answers[i], _, _ = strings.Cut(l, "\t")
	}
	return answers
}

// THE CATALOGUE, ANSWERED: what a session may run on a machine in a tier
// that answers as the defaults do, command by command. A read is allowed
// only where nothing it could be given writes, runs something or reaches
// the network; the rest asks or refuses, and an argument naming a secret
// refuses whatever the command.
var catalogueAnswers = []struct{ command, want string }{
	// Reads: looking around.
	{"pwd", "allow"},
	{"ls -la /etc", "allow"},
	{"cd /var/log && ls -lt", "allow"},
	{"cat /etc/os-release", "allow"},
	{"tail -n 100 /var/log/syslog", "allow"},
	{"tail -f /var/log/nginx/error.log", "allow"},
	{"grep -i error /var/log/syslog", "allow"},
	{"grep -c 'connection refused' /var/log/syslog", "allow"},
	{"find /etc -name '*.conf' -mtime -1", "allow"},
	{"systemctl status nginx", "allow"},
	{"systemctl is-active nginx && systemctl is-enabled nginx", "allow"},
	{"journalctl -u nginx -n 100 --no-pager", "allow"},
	{"journalctl -b -p err", "allow"},
	{"df -h", "allow"},
	{"du -sh /var/log", "allow"},
	{"free -m", "allow"},
	{"ps aux", "allow"},
	{"ps aux | grep nginx", "allow"},
	{"sort /etc/passwd | uniq -c", "allow"},
	{"ip addr", "allow"},
	{"ip -br a", "allow"},
	{"lsof -i :443", "allow"},
	{"lsof -p 1", "allow"},
	{"dpkg -l nginx", "allow"},
	{"apt list --installed", "allow"},
	{"apt policy nginx", "allow"},
	{"docker ps -a", "allow"},
	{"docker logs --tail 50 web", "allow"},
	{"uptime; date; hostname; uname -a; whoami", "allow"},
	{"date -u +%F", "allow"},
	{"less /var/log/syslog", "allow"},
	{"which nginx", "allow"},
	{"systemctl show -p MainPID nginx", "allow"},
	{"cat /etc/ssl/openssl.cnf", "allow"},
	{"cat /proc/1/cmdline", "allow"}, // ps aux shows every process's anyway
	{"diff -q /etc/nginx/nginx.conf /srv/nginx.conf", "allow"},
	{"diff --brief -r /etc/nginx /srv/nginx", "ask"},
	{"grep error records.log", "allow"},
	{"grep -i receipt /var/log/recovery/x", "allow"},
	{"lspci -nnk", "allow"},
	{"lspci -vvv -s 00:1f.3", "allow"},
	{"cmp -l a b", "allow"},
	{"lsblk /dev/nvme0n1", "allow"},
	{"df -h /dev/sda1", "allow"},
	{"systemctl start nginx.service", "ask"},
	// diff of two directories prints the files they share by name, one
	// level down without -r, and no word says which is a directory.
	{"diff -u /etc/nginx/nginx.conf /srv/nginx.conf", "ask"},
	{"diff -a /proc/1 /proc/2", "ask"},

	// Writes, asked about.
	{"systemctl restart nginx", "ask"},
	{"systemctl daemon-reload", "ask"},
	{"apt update", "ask"},
	{"apt install nginx", "ask"},
	{"mkdir -p /srv/app", "ask"},
	{"cp a b", "ask"},
	{"grep -r listen /etc", "ask"},
	{"grep -Rn x .", "ask"},
	{"grep --recursive x .", "ask"},
	{"grep --directories=recurse x .", "ask"},
	{"grep -d rec x .", "ask"},
	{"grep -d recurse x .", "ask"},
	{"grep -drecu x .", "ask"},
	{"grep --dir=recur x .", "ask"},
	{"sort -o /etc/passwd /tmp/x", "ask"},
	{"diff -rN /home/ops /var/empty", "ask"},
	{"diff -qr a b", "ask"},
	{"diff --rec a b", "ask"},
	{"diff -N a b", "ask"},
	{"diff --new-f a b", "ask"},
	{"diff --unid /var/empty /home/ops", "ask"},
	{"journalctl --up", "ask"},
	{"journalctl --update-catalog", "ask"},
	{"journalctl --vacuum-time=1d", "ask"},
	{"journalctl --rot", "ask"},
	{"journalctl --cursor-file=/etc/passwd", "ask"},
	{"journalctl --image=/srv/disk.raw", "ask"},
	{"systemctl cat foo --image=/srv/disk.raw", "ask"},
	{"systemctl is-enabled --im /srv/disk.raw foo", "ask"},
	{"systemctl list-unit-files --root=/srv/tree", "ask"},
	{"lspci -Q -O net.cache_name=/home/ops/.bashrc", "ask"},
	{"lspci -q", "ask"},
	{"lspci -vQ", "ask"},
	{"lspci -O net.domain=pci.example", "ask"},
	{"lspci -F /home/ops/dump", "ask"},
	{"lspci -i /srv/ids", "ask"},
	{"dmesg -C", "ask"},
	{"file -C -m x", "ask"},
	{"find / -fprint /etc/x", "ask"},
	{"lsof -i @probe.example.com", "ask"},
	{"lsof -iTCP@probe.example.com:443", "ask"},
	// A file printed through an option it is written onto, which no
	// secret glob sees: -f.kube/config is the parts -f.kube and config.
	{"date -f.kube/config", "ask"},
	{"date -uf.netrc", "ask"},
	{"date --file=x", "ask"},
	{"dmesg -F.kube/config", "ask"},
	{"dmesg --kmsg-file=x", "ask"},
	{"file -f.docker/config.json", "ask"},
	{"file -m.npmrc /etc/hostname", "ask"},
	{"findmnt -F.my.cnf", "ask"},
	{"last -f.boto", "ask"},
	{"apt-cache policy -p /home/ops/.profile", "ask"},
	{"apt-cache show -s/srv/x bash", "ask"},
	{"apt policy -p /home/ops/.profile", "ask"},
	{"apt search x -s /home/ops/.profile", "ask"},
	{"apt depends -p/srv/x bash", "ask"},
	{"apt rdepends bash -s /srv/x", "ask"},
	{"apt showsrc -p /srv/x bash", "ask"},
	{"apt-cache show --pkg-cache=/etc/passwd bash", "refuse"}, // apt -o's too

	// What no operation names, or no rule can read, asked about.
	{"sudo apt update", "ask"},
	{"awk '{print $1}' /etc/passwd", "ask"},
	{"sed -i s/a/b/ x", "ask"},
	{"xargs rm < list", "ask"},
	{"bash -c id", "ask"},
	{"ls $(id)", "ask"},
	{"ls `id`", "ask"},
	{"less '+!id' /etc/hosts", "ask"}, // ! is unreadable, quoted or not
	{"echo hi > /tmp/x", "ask"},
	{"ls & rm x", "ask"},
	{"ls; python3 x", "ask"},
	{"ps e", "ask"},
	{"ps -p 1 e", "ask"},
	{"hostname evil", "ask"},
	{"mount /dev/sda1 /mnt", "ask"},
	{"ip a a 10.0.0.1/24 dev eth0", "ask"},
	{"ip -b cmds", "ask"},
	{"uniq a b", "ask"},
	{"tar xf x.tar", "ask"},
	{"rpm -qa", "ask"},
	{"command -v ls", "ask"}, // csh runs a program named command
	{"kill %1", "ask"},       // fish reads a word beginning % as a process
	// ss resolves any filter word it does not know as a host's name, over
	// DNS, a name of the argument's choosing: no ss is a read, and none is
	// worth the guard every filter word would need.
	{"ss -tlnp", "ask"},
	{"ss -K dst 10.0.0.1", "ask"},

	// What runs is decided, and not what only sets how it runs: time, and
	// the tier's env names, as the shell's assignments or env's.
	{"LANG=C ls -la /etc", "allow"},
	{"LC_ALL=C LANG=C sort /etc/passwd", "allow"},
	{"TZ=UTC date", "allow"},
	{"env TZ=UTC date -u", "allow"},
	{"COLUMNS=200 systemctl status nginx", "allow"},
	{"time ls", "allow"},
	{"env LANG=C time -p ls", "allow"},
	{"TZ=Europe/London date", "allow"},
	{"time -p env LANG=C ls", "ask"}, // zsh's time runs a command named -p
	{"time '-p' ls", "ask"},          // and so does bash's, quoted
	{"LANG=C systemctl restart nginx", "ask"},
	{"time rm x", "refuse"},
	{"env rm x", "refuse"},
	{"LANG=C rm x", "refuse"},
	{"LANG=x/.ssh/id_rsa ls", "refuse"}, // an arg rule sees the value
	// A value naming a file of the session's choosing, whose locale or zone
	// data the program allowed would parse.
	{"LANG=/root/.ssh/id_rsa ls", "ask"},
	{"LC_ALL=/tmp/l ls", "ask"},
	{"TZ=:/tmp/z date", "ask"},
	{"TZ=../../../tmp/z date", "ask"},
	{"PATH=/tmp ls", "ask"}, // a name no tier may list
	{"LD_PRELOAD=/tmp/x.so ls", "ask"},
	{"PAGER=id systemctl status nginx", "ask"},
	{"SYSTEMD_PAGER=sh systemctl status", "ask"},
	{"LANG=C", "ask"},         // the shell's own, for whatever comes next
	{"env -i ls", "ask"},      // an option changes what runs
	{"time LANG=C ls", "ask"}, // dash's /usr/bin/time runs LANG=C
	{"LANG=C time ls", "ask"},
	{"'LANG=C' ls", "ask"},
	{"env", "refuse"}, // the environment, printed

	// A precommand runs the command after it, which is what is decided.
	{"exec ls -la /etc", "allow"},
	{"command cat /etc/os-release", "allow"},
	{"builtin cd /etc && ls", "allow"},
	{"command systemctl restart nginx", "ask"},
	{"command rm x", "refuse"},
	{"exec env rm x", "refuse"},
	{"command cat /etc/shadow", "refuse"},
	{"command env LANG=C time -p ls", "allow"},
	{"'command' ls", "ask"}, // csh runs a program named command
	{"LANG=C command ls", "ask"},
	{"env command ls", "ask"},
	{"time exec ls", "ask"},
	{"command command ls", "ask"},

	// Double-quoted words are their content, as single-quoted ones are.
	{`grep -c "connection refused" /var/log/syslog`, "allow"},
	{`find /etc -name "*.conf"`, "allow"},
	{`"ls" /etc`, "allow"},
	{`cat "/root/.ssh/id_ed25519"`, "refuse"},
	{`find / -name "id_*"`, "refuse"},
	{`systemctl restart "nginx"`, "ask"},
	{`rm -rf "/srv/app"`, "refuse"},
	{`echo "$HOME"`, "ask"},           // expanded inside double quotes
	{`echo "a\"b"`, "ask"},            // escaped
	{"echo \"`id`\"", "ask"},          // run
	{`less "+!id" /etc/hosts`, "ask"}, // csh's history

	// Redirections to and from /dev/null are no words of the command.
	{"ls -la /etc >/dev/null", "allow"},
	{"grep -q nginx /etc/passwd </dev/null >/dev/null && systemctl status nginx", "allow"},
	{"systemctl restart nginx >/dev/null", "ask"},
	{"rm x </dev/null", "refuse"},
	{"cat /etc/shadow >/dev/null", "refuse"},
	{"ls 2>/dev/null", "ask"}, // csh's argument 2
	{"ls > /dev/null", "ask"},
	{"ls >/dev/null | wc -l", "ask"}, // csh's ambiguous redirect
	{"ls >/tmp/x", "ask"},
	{"ls " + strings.Repeat("a", 8<<10), "ask"}, // longer than frisket reads

	// The environment, printed, which is as often where a secret is as a
	// file: guarded in each spelling of it the catalogue knows -- its usual
	// paths, env's options that run nothing, a property's or a column's
	// name in a list -- and what it does not know is asked about.
	{"printenv", "refuse"},
	{"printenv AWS_SECRET_ACCESS_KEY", "refuse"},
	{"env LANG=C", "refuse"},
	{"exec env", "refuse"},
	{"command printenv HOME", "refuse"},
	{"env | grep -i token", "refuse"},
	{"printenv | sort", "refuse"},
	{"set", "refuse"},
	{"export -p", "refuse"},
	{"declare -p", "refuse"},
	{"declare -x", "refuse"},
	{"typeset", "refuse"},
	{"readonly -p", "refuse"},
	{"setenv", "refuse"},
	{"systemctl show-environment", "refuse"},
	{"cat /proc/self/environ", "refuse"},
	{"ps e", "ask"},
	{"local", "refuse"}, // zsh's lists every parameter, the environment's too
	{"/usr/bin/env", "refuse"},
	{"/bin/env", "refuse"},
	{"/usr/bin/printenv", "refuse"},
	{"/usr/bin/printenv HOME", "refuse"},
	{"env -0", "refuse"},
	{"env --null", "refuse"},
	{"env -u X", "refuse"},
	{"exec env -0", "refuse"},
	{"env -0 ls", "ask"},
	{"/usr/bin/env ls", "ask"},
	{"ps -o environ -p 1", "refuse"},
	{"ps -o environ= -p 1", "refuse"},
	{"ps -o pid,environ -p 1", "refuse"},
	{"ps -o environ:999 -p 1", "refuse"},
	{"ps -o cmd,environ -p 1", "refuse"},
	{"ps -o pid,environ -p 1,2,3", "refuse"},
	{"ps -o pid,cmd -p 1", "allow"},
	{"systemctl --user show-environment", "refuse"},
	{"systemctl -q show-environment", "refuse"},
	{"systemctl show", "refuse"},
	{"systemctl show --user", "refuse"},
	{"systemctl show --all", "refuse"},
	{"systemctl show -p Environment", "refuse"},
	{"systemctl show --property=Environment", "refuse"},
	{"systemctl show -p Environment --value", "refuse"},
	{"systemctl show --user -p Environment", "refuse"},
	{"systemctl --user show -p Environment", "refuse"},
	{"systemctl show -p MainPID,Environment nginx", "refuse"},
	{"systemctl show -p Version", "allow"},
	{"systemctl show nginx", "allow"},

	// Guarded, refused.
	{"rm -rf /srv/app", "refuse"},
	{"ls && rm x", "refuse"},
	{"reboot", "refuse"},
	{"systemctl reboot", "refuse"},
	{"systemctl mask nginx", "refuse"},
	{"kill -9 1", "refuse"},
	{"chmod 777 /etc", "refuse"},
	{"apt remove nginx", "refuse"},
	{"find / -name x -delete", "refuse"},
	{"find . -exec id ';'", "refuse"},
	{"find . -execdir id +", "refuse"},
	{"find . -okdir id ';'", "refuse"},
	{"less '+|a id' /etc/hosts", "refuse"},
	{"less +G /var/log/syslog", "refuse"},
	{"more +/x /etc/hosts", "refuse"},
	{"less -o /etc/passwd x", "refuse"},
	{"less --log-file=/etc/x y", "refuse"},
	{"less -k keys x", "refuse"},
	{"date 01010000", "refuse"},
	{"date -s now", "refuse"},
	{"date --set=tomorrow", "refuse"},
	{"systemctl -H other status nginx", "refuse"},
	{"systemctl status nginx --host=other", "refuse"},
	{"systemctl status nginx --ho=other", "refuse"},
	{"systemctl cat --machine=other nginx", "refuse"},
	{"systemctl status -M other nginx", "refuse"},
	{"systemctl show -aMother nginx", "refuse"},
	{"systemctl show --mach=other nginx", "refuse"},
	{"lspci -H1", "refuse"},
	{"lspci -A intel-conf1", "refuse"},
	{"lspci -M", "refuse"},
	{"lspci -xxxx", "refuse"},
	{"lspci -vxxx", "refuse"},
	{"lspci -x -x -x", "refuse"},
	{"lspci -xx -x", "refuse"},
	{"lspci -v -x", "refuse"},
	{"apt install ./x.deb", "refuse"},
	{"apt install -o APT::Update::Pre-Invoke::=id nginx", "refuse"},
	{"apt list -oDir::Cache=/etc", "refuse"},
	{"apt update -c /tmp/apt.conf", "refuse"},
	{"apt-get -yo Dpkg::Pre-Invoke::=id install nginx", "refuse"},
	{"dpkg -L --pre-invoke=id", "refuse"},
	{"docker rm -f web", "refuse"},
	{"dd if=/dev/zero of=/dev/sda", "refuse"},
	{"sort --compress-program=sh x", "refuse"},
	{"sort -S 1K --co=sh x", "refuse"},
	{"sort -o out --compress-program=sh x", "refuse"},
	{"systemctl start reboot.target", "refuse"},
	{"systemctl restart poweroff.target", "refuse"},
	{"systemctl start kexec.target", "refuse"},
	{"systemctl start rescue.target", "refuse"},
	{"systemctl start systemd-reboot.service", "refuse"},
	{"systemctl --no-block start halt.target", "refuse"},
	{"systemctl soft-reboot", "refuse"},
	{"systemctl hybrid-sleep", "refuse"},
	{"systemctl suspend-then-hibernate", "refuse"},
	{"systemctl exit", "refuse"},
	{"systemctl default", "refuse"},
	{"systemctl start exit.target", "refuse"},
	{"systemctl start systemd-exit.service", "refuse"},
	{"systemctl start factory-reset.target", "refuse"},
	{"systemctl start systemd-factory-reset-request.service", "refuse"},
	{"head -c 100M /dev/sda1", "refuse"},
	{"cat /dev/nvme0n1p2", "refuse"},
	{"grep -a root: /dev/mapper/root", "refuse"},
	{"tail -c 1G /dev/disk/by-uuid/0a1b", "refuse"},
	{"cat /dev/ubuntu-vg/ubuntu-lv", "refuse"},
	{"head -c 1G /dev/sde1", "refuse"},
	{"cat /dev/block/8:1", "refuse"},
	{"cat /dev/root", "refuse"},
	{"cat /dev/md0", "refuse"},
	{"cat /dev/loop0", "refuse"},
	{"cat /dev/zd0", "refuse"},
	{"cat /dev/nbd0", "refuse"},
	{"cat /dev/hda1", "refuse"},
	{"date -f /dev/nvme0n1p2", "refuse"},
	{"dmesg -F /dev/sda1", "refuse"},
	{"last -f /dev/sda1", "refuse"},
	{"who /dev/vda1", "refuse"},
	{"diff -q /dev/null /etc/hosts", "allow"}, // not a disk
	{"dmesg | grep -i mem", "allow"},          // a search for the word, not memory
	{"grep mem /proc/meminfo", "allow"},
	{"cat /dev/mem", "refuse"},
	{"head -c 4096 /dev/kmem", "refuse"},
	{"cat /proc/self/mem", "refuse"},
	{"tail -c 1 /proc/1234/mem", "refuse"},
	{"cat /proc/kcore", "refuse"},
	{"systemctl cat -C alice foo.service", "refuse"},
	{"systemctl show --capsule=alice foo.service", "refuse"},
	{"systemctl status -C alice", "refuse"},
	{"systemctl --ca=alice status x", "refuse"},
	{"systemctl show -p CPUUsageNSec x", "allow"},
	{"sort --fil f0", "ask"},
	{"sort --files0=f0", "ask"},
	{"sort --files0-from=f0", "ask"},
	{"sort -t , -k 2 x", "allow"},
	{"cat /root/notes", "allow"},

	// Secrets, refused whatever reads them.
	{"cat /root/.ssh/id_ed25519", "refuse"},
	{"cat id_rsa", "refuse"},
	{"ls /home/ops/.ssh", "refuse"},
	{"cd /home/ops/.ssh && ls", "refuse"},
	{"cd /home/ops && cat .ssh/authorized_keys", "refuse"},
	{"cat '/root/.ssh/id_ed25519'", "refuse"},
	{"cat /etc/ssh/ssh_host_ed25519_key", "refuse"},
	{"cat /etc/shadow", "refuse"},
	{"cd /etc && cat shadow", "refuse"},
	{"getent shadow", "refuse"},
	{"cat /proc/1/environ", "refuse"},
	{"cat .env", "refuse"},
	{"cat config/.env.production", "refuse"},
	{"grep x /run/secrets/db", "refuse"},
	{"cat /etc/ssl/private/site.key", "refuse"},
	{"head ~/.bash_history", "ask"}, // ~ is no plain word
	{"head /root/.bash_history", "refuse"},
	{"tail /home/ops/.aws/credentials", "refuse"},
	{"cat /home/ops/.docker/config.json", "refuse"},
	{"grep --file=/root/.netrc x", "refuse"},
	{"python3 /root/.ssh/x", "refuse"},
	{"find / -name 'id_*'", "refuse"},
	{"cat /root/.config/gcloud/application_default_credentials.json /root/.config/gcloud/access_tokens.db", "refuse"},
	{"cat /srv/app/application_default_credentials.json", "refuse"},
	{"cat /srv/app/access_tokens.db", "refuse"},
	{"cat /root/.config/gh/hosts.yml", "refuse"},
	{"cat /root/.azure/accessTokens.json /root/.azure/msal_token_cache.json", "refuse"},
	{"cat /srv/accessTokens.json", "refuse"},
	{"cat /etc/mysql/debian.cnf", "refuse"},
	{"cat /root/.terraform/terraform.tfstate", "refuse"},
	{"cat infra/terraform.tfstate.backup", "refuse"},
	{"cat infra/prod.tfvars", "refuse"},
	{"cat /root/.config/rclone/rclone.conf", "refuse"},
	{"cat /root/.local/share/containers/auth.json", "refuse"},
	{"cat /etc/environment", "refuse"},
	{"cat /srv/app/deploy_key", "refuse"},
	{"cat /srv/app/backup-key", "refuse"},
	{"cat /etc/wireguard/wg0.conf", "refuse"},
	{"cat /etc/NetworkManager/system-connections/home.nmconnection", "refuse"},
	{"cat /etc/kubernetes/admin.conf", "refuse"},
	{"cat /etc/rancher/k3s/k3s.yaml", "refuse"},
	{"cat /home/ops/.s3cfg /home/ops/.boto", "refuse"},
	{"cat /var/lib/tailscale/tailscaled.state", "refuse"},
	{"cat /etc/letsencrypt/accounts/acme/directory/abc/private_key.json", "refuse"},
	{"cat /run/secrets.d/1/modem-password", "refuse"},
	{"ls /run/secrets.d/1", "refuse"},
	{"cat /run/secrets-for-users.d/1/dan-password", "refuse"},
	{"cat /srv/db/dockerhub-password", "refuse"},
	{"grep -i password /var/log/auth.log", "refuse"}, // as *token* is
	{"cat /home/ops/.config/sops/age/keys.txt", "refuse"},
	{"cat /var/lib/sops-nix/key.txt", "refuse"},
	{"cat /run/agenix/db", "refuse"},
	{"ls /run/keys", "refuse"},
	{"cat /etc/credstore/x", "refuse"},
	{"getent passwd ops", "allow"},
	{"cat '=deploy'", "allow"}, // quoted, = is itself to every shell
	{"cat =deploy", "ask"},     // zsh reads it as deploy's path
}

func TestTheCatalogueAnswersCommandsAsTheirClassesSay(t *testing.T) {
	r := route(t, config(), "")
	for _, tc := range catalogueAnswers {
		if got := decide(r, tc.command); got != tc.want {
			t.Errorf("%s: %s, not %s", tc.command, got, tc.want)
		}
	}
}

// A secret named anywhere refuses: whatever the catalogue's command, in
// whatever compound, an argument that spells a path to one is refused in a
// tier that refuses what is guarded.
func TestASecretNamedAnywhereIsRefused(t *testing.T) {
	r := route(t, config(), "")
	ops, err := LoadCatalogue(catalogue, linuxCategories)
	if err != nil {
		t.Fatal(err)
	}
	var firsts []string
	for _, o := range ops {
		for _, p := range o.Commands {
			// env with more words is not env but what it runs: env
			// /root/.ssh/x runs the file, whose name is no argument.
			if f := strings.Fields(p)[0]; f != "env" {
				firsts = append(firsts, f)
			}
		}
	}
	slices.Sort(firsts)
	firsts = slices.Compact(firsts)
	secrets := []string{"/root/.ssh/id_ed25519", ".ssh", "/etc/shadow", "id_rsa", "--file=/home/ops/.aws/credentials",
		"/proc/1/environ", "app/.env", "/run/secrets/db", "/etc/ssl/private/site.key", "'/root/.ssh'", "/home/ops/.bash_history",
		"/run/secrets.d/1/modem-password", "/var/lib/sops-nix/key.txt"}
	word := rapid.StringMatching(`[a-z0-9./=-]{1,12}`)
	rapid.Check(t, func(t *rapid.T) {
		simple := func(secret bool) string {
			ws := []string{rapid.SampledFrom(firsts).Draw(t, "command")}
			ws = append(ws, rapid.SliceOfN(word, 0, 3).Draw(t, "args")...)
			if secret {
				at := rapid.IntRange(1, len(ws)).Draw(t, "at")
				ws = slices.Insert(ws, at, rapid.SampledFrom(secrets).Draw(t, "secret"))
			}
			return strings.Join(ws, " ")
		}
		n := rapid.IntRange(1, 3).Draw(t, "simple commands")
		with := rapid.IntRange(0, n-1).Draw(t, "with the secret")
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, simple(i == with))
		}
		command := strings.Join(parts, rapid.SampledFrom([]string{" && ", "; ", " | ", " || "}).Draw(t, "joined by"))
		if readable(r, command) {
			if got := decide(r, command); got != "refuse" {
				t.Fatalf("%s: %s", command, got)
			}
		}
	})
}

// THE MATCHER TESTED IS THE ONE RUN: decide, which every test of what the
// catalogue answers goes through, is frisket's execrule as go.mod pins it,
// and a session is decided by the frisket the flake runs. So that frisket
// itself answers the same commands -- the catalogue's examples and commands
// made of its own words, secrets, devices, env names and what no rule can
// read -- under routes that answer by every kind of rule, and must answer
// them alike. Two frisket that read a word differently, split it elsewhere
// or reserved another would otherwise leave every test here green and the
// secrets unrefused.
func TestTheMatcherTheTestsUseDecidesAsTheFrisketSessionsRun(t *testing.T) {
	ops, err := LoadCatalogue(catalogue, linuxCategories)
	if err != nil {
		t.Fatal(err)
	}
	var firsts []string
	for _, o := range ops {
		for _, p := range o.Commands {
			firsts = append(firsts, strings.Fields(p)[0])
		}
	}
	slices.Sort(firsts)
	firsts = slices.Compact(firsts)
	commands := make([]string, 0, len(catalogueAnswers))
	for _, tc := range catalogueAnswers {
		commands = append(commands, tc.command)
	}
	words := []string{"-la", "-r", "-f.kube/config", "-f.netrc", "--key=id_rsa", "--host=x", "-F", "-o", "--file=/root/.netrc", "/dev/sda1", "/dev/vg/lv",
		"/etc/shadow", ".ssh", "x.pem", "/run/secrets.d/1/x", "status", "restart", "nginx", "list",
		"'a b'", "'+!id'", "$(id)", "=x", "a=b", "**", "time", "-exec", "+G", "reboot.target", "01010000",
		"env", "LANG=C", "LC_ALL=/root/.ssh/x", "PATH=/tmp", "-p",
		`"a b"`, `"/root/.ssh/id_rsa"`, `"$x"`, "%self", ">/dev/null", "</dev/null", "2>/dev/null", "exec", "command", "printenv"}
	rapid.Check(t, func(t *rapid.T) {
		var parts []string
		for range rapid.IntRange(1, 3).Draw(t, "simple commands") {
			ws := []string{rapid.SampledFrom(append(firsts, "awk", "time", "X=1", "env", "LANG=C", "TZ=UTC", "LD_PRELOAD=x", "exec", "command", "builtin", `"ls"`)).Draw(t, "command")}
			ws = append(ws, rapid.SliceOfN(rapid.SampledFrom(words), 0, 4).Draw(t, "args")...)
			parts = append(parts, strings.Join(ws, " "))
		}
		commands = append(commands, strings.Join(parts, rapid.SampledFrom([]string{" && ", ";", " | ", "||", " & "}).Draw(t, "joined by")))
	})
	unmatchedAllow := config()
	unmatchedAllow.Tiers["trusted"] = Tier{Writes: "ask", Guarded: "ask", Unmatched: "allow"}
	for _, tc := range []struct {
		name  string
		c     Config
		extra string
	}{
		{"the defaults", config(), ""},
		{"categories and patterns", config(), `{"allow": ["category:search", "category:files", "find-run", "docker compose ps **"], "ask": ["category:read"], "refuse": ["ls **"]}`},
		{"unmatched allowed", unmatchedAllow, ""},
	} {
		r := route(t, tc.c, tc.extra)
		for i, want := range frisketDecide(t, r, commands) {
			if got := decide(r, commands[i]); got != want {
				t.Errorf("%s: %s: the execrule tested with says %s, the frisket run %s", tc.name, commands[i], got, want)
			}
		}
	}
}

// What frisket loads: the route made with the defaults, and with every
// operation answered "ask", which makes a rule of every arg operation.
func TestFrisketLoadsTheCatalogueAsEveryTierAnswersIt(t *testing.T) {
	for _, tier := range []Tier{
		{Writes: "ask", Guarded: "refuse", Unmatched: "ask"},
		{Writes: "ask", Guarded: "ask", Unmatched: "ask"},
		{Writes: "refuse", Guarded: "refuse", Unmatched: "refuse"},
		{Writes: "allow", Guarded: "allow", Unmatched: "allow"},
	} {
		c := config()
		c.Tiers["trusted"] = tier
		r := route(t, c, "")
		if out, err := frisketCheck(t, []policy.SSHRoute{r}); err != nil {
			t.Errorf("frisket refused the route a tier of %+v makes: %v: %s", tier, err, out)
		}
	}
}

// The catalogue is what CheckCatalogue holds it to, and has every class.
func TestTheCatalogueIsWellFormed(t *testing.T) {
	ops, err := LoadCatalogue(catalogue, linuxCategories)
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]int{}
	for _, o := range ops {
		classes[o.Class]++
	}
	if classes["read"] == 0 || classes["write"] == 0 || classes["guarded"] == 0 {
		t.Errorf("the catalogue is missing a class: %v", classes)
	}
	// Every secret is guarded: an arg operation of every command, so that
	// it holds whatever reads it, or commands that print one themselves,
	// as the environment's do.
	for _, o := range ops {
		if o.Category == "secrets" && (o.Class != "guarded" || len(o.Commands) != 0 && len(o.Args) != 0) {
			t.Errorf("%s is a secret, but not guarded, or an arg operation of only some commands", o.ID)
		}
	}
}

func TestACatalogueThatCouldNotBeLoadedIsRefused(t *testing.T) {
	ok := Operation{ID: "list-directory", Summary: "List", Class: "read", Category: "navigate", Commands: []string{"ls **"}}
	for _, tc := range []struct {
		name string
		ops  []Operation
		said string
	}{
		{"an id that is not kebab-case", []Operation{{ID: "List", Summary: "s", Class: "read", Category: "read", Commands: []string{"ls **"}}}, "not kebab-case"},
		{"an id twice", []Operation{ok, {ID: "list-directory", Summary: "s", Class: "read", Category: "read", Commands: []string{"dir **"}}}, "another operation's"},
		{"no summary", []Operation{{ID: "a", Class: "read", Category: "read", Commands: []string{"a"}}}, "no summary"},
		{"a class of its own", []Operation{{ID: "a", Summary: "s", Class: "admin", Category: "read", Commands: []string{"a"}}}, "class"},
		{"a category not in the list", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "misc", Commands: []string{"a"}}}, "category"},
		{"nothing to match", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read"}}, "no commands and no args"},
		{"an arg read", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Args: []string{"x*"}}}, "never a read"},
		{"a pattern twice", []Operation{ok, {ID: "b", Summary: "s", Class: "write", Category: "read", Commands: []string{"ls **"}}}, "list-directory's too"},
		{"a glob twice for a command", []Operation{
			{ID: "a", Summary: "s", Class: "write", Category: "read", Commands: []string{"ls **"}, Args: []string{"x*"}},
			{ID: "b", Summary: "s", Class: "guarded", Category: "read", Commands: []string{"ls **"}, Args: []string{"x*"}},
		}, "a's too"},
		{"a pattern with two spaces", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"ls  **"}}}, "one space"},
		{"** before the end", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"ls ** x"}}}, "only the last word"},
		{"a quote in a pattern", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"ls 'x'"}}}, "or plain"},
		{"an assignment first", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"X=1 **"}}}, "assignment"},
		{"a reserved word first", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"time **"}}}, "reserved"},
		{"env with a command", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"env **"}}}, `"env" is only ever alone`},
		{"a word beginning =", []Operation{{ID: "a", Summary: "s", Class: "read", Category: "read", Commands: []string{"cat =deploy"}}}, "begins ="},
		{"a glob of every word", []Operation{{ID: "a", Summary: "s", Class: "guarded", Category: "read", Args: []string{"**"}}}, "** says no more"},
		{"a glob of stars", []Operation{{ID: "a", Summary: "s", Class: "guarded", Category: "read", Args: []string{"*"}}}, "every word"},
		{"a glob no readable word holds", []Operation{{ID: "a", Summary: "s", Class: "guarded", Category: "read", Args: []string{"x!"}}}, "printable ASCII"},
	} {
		err := CheckCatalogue(tc.ops, linuxCategories)
		if err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := CheckCatalogue([]Operation{ok}, linuxCategories); err != nil {
		t.Errorf("one operation was refused: %v", err)
	}
}

// THE ROUTE: one for each machine, by its name, with the machine's
// credential and the grant's address, user and keys, in name order.
func TestEachMachineIsARouteWithTheMachinesCredential(t *testing.T) {
	k1, k2 := hostKey(t, "a"), hostKey(t, "b")
	c := config()
	c.Identity = "SHA256:" + strings.Repeat("A", 43)
	p, said, err := prepare(t, c, "trusted", `{"hosts": {
		"server": {"address": "192.168.1.10", "user": "ops", "hostKeys": ["`+k1+`"]},
		"gateway": {"address": "[fd00::1]:2222", "user": "root", "hostKeys": ["`+k2+`"]}}}`)
	if err != nil || said != "" {
		t.Fatalf("%v: %s", err, said)
	}
	if len(p.Routes) != 0 || len(p.Allow) != 0 || len(p.Env) != 0 || len(p.Files) != 0 {
		t.Errorf("SSH added more than its routes: %+v", p)
	}
	if len(p.SSH) != 2 {
		t.Fatalf("not two routes: %+v", p.SSH)
	}
	g, s := p.SSH[0], p.SSH[1]
	if g.Name != "gateway" || g.Address != "[fd00::1]:2222" || g.User != "root" || !slices.Equal(g.HostKeys, []string{k2}) {
		t.Errorf("gateway is not the grant's: %+v", g)
	}
	if s.Name != "server" || s.Address != "192.168.1.10" || s.User != "ops" || !slices.Equal(s.HostKeys, []string{k1}) {
		t.Errorf("server is not the grant's: %+v", s)
	}
	for _, r := range p.SSH {
		if r.Agent != "/run/user/1000/gcr/ssh" || r.KeyFile != "" || r.Identity != c.Identity || r.Unmatched != "ask" {
			t.Errorf("%s does not log in as the machine says: %+v", r.Name, r)
		}
		if !slices.Equal(r.Env, defaultEnv) {
			t.Errorf("%s's env is not the tier's: %q", r.Name, r.Env)
		}
	}
	if out, err := frisketCheck(t, p.SSH); err != nil {
		t.Errorf("frisket refused the routes: %v: %s", err, out)
	}

	c.Agent, c.KeyFile = "", "/home/alice/.ssh/frisket"
	if r := route(t, c, ""); r.Agent != "" || r.KeyFile != "/home/alice/.ssh/frisket" {
		t.Errorf("a key file is not what logs in: %+v", r)
	}
}

func rule(r policy.SSHRoute, command, arg string) (policy.ExecRule, bool) {
	at := slices.IndexFunc(r.Exec, func(e policy.ExecRule) bool { return e.Command == command && e.Arg == arg })
	if at < 0 {
		return policy.ExecRule{}, false
	}
	return r.Exec[at], true
}

// THE ANSWERS: a read allowed, a write as the tier's writes and a guarded
// operation as its guarded, each rule carrying its operation; an arg
// operation a rule only where it tightens.
func TestEachOperationIsAnsweredByItsClass(t *testing.T) {
	r := route(t, config(), "")
	for _, tc := range []struct {
		command, arg, want, id string
	}{
		{"ls **", "", "allow", "list-directory"},
		{"systemctl restart **", "", "ask", "service-restart"},
		{"rm **", "", "refuse", "remove"},
		{"grep **", "-*r*", "ask", "search-recursive"},
		{"find **", "-delete", "refuse", "find-delete"},
		{"", ".ssh", "refuse", "secret-ssh"},
	} {
		e, ok := rule(r, tc.command, tc.arg)
		if !ok {
			t.Errorf("no rule %q [arg %q]", tc.command, tc.arg)
			continue
		}
		if outcome(e) != tc.want || e.Operation == nil || e.Operation.ID != tc.id {
			t.Errorf("%q [arg %q] is %s by %+v, not %s by %s", tc.command, tc.arg, outcome(e), e.Operation, tc.want, tc.id)
		}
	}
	c := config()
	c.Tiers["trusted"] = Tier{Writes: "allow", Guarded: "allow", Unmatched: "ask"}
	r = route(t, c, "")
	if _, ok := rule(r, "", ".ssh"); ok {
		t.Error("an arg operation answered allow is a rule")
	}
	if e, _ := rule(r, "rm **", ""); outcome(e) != "allow" {
		t.Errorf("guarded allowed is %s", outcome(e))
	}
}

// THE PROJECT'S LISTS: an id before its category, a category before the
// tier; a pattern in place of the catalogue's rule of the same pattern,
// whose operation it keeps, or a rule of its own.
func TestTheProjectsListsDecideBeforeTheTier(t *testing.T) {
	r := route(t, config(), `{
		"allow": ["service-restart", "secret-environment", "docker compose ps **"],
		"ask": ["category:files", "rm **"],
		"refuse": ["category:services", "ls **"]}`)
	for _, tc := range []struct{ command, arg, want, id string }{
		{"systemctl restart **", "", "allow", "service-restart"},
		{"systemctl start **", "", "refuse", "service-start"},
		{"systemctl status **", "", "refuse", "service-status"},
		{"cp **", "", "ask", "copy"},
		{"rm **", "", "ask", "remove"},
		{"ls **", "", "refuse", "list-directory"},
		{"docker compose ps **", "", "allow", ""},
	} {
		e, ok := rule(r, tc.command, tc.arg)
		id := ""
		if e.Operation != nil {
			id = e.Operation.ID
		}
		if !ok || outcome(e) != tc.want || id != tc.id {
			t.Errorf("%q is %s by %q, not %s by %q", tc.command, outcome(e), id, tc.want, tc.id)
		}
	}
	if _, ok := rule(r, "", ".env"); ok {
		t.Error("a secret the project allows is still refused")
	}
	if got := decide(r, "cat .env"); got != "allow" {
		t.Errorf("cat .env is %s", got)
	}

	// A pattern as literal as the catalogue's decides only where it is the
	// stricter, and one more literal decides.
	r = route(t, config(), `{"allow": ["systemctl restart nginx", "apt install -y *"], "ask": ["ls *"]}`)
	for _, tc := range []struct{ command, want string }{
		{"systemctl restart nginx", "allow"},
		{"systemctl restart sshd", "ask"},
		{"apt install -y nginx", "allow"},
		{"ls /etc", "ask"},
		{"ls", "allow"},
	} {
		if got := decide(r, tc.command); got != tc.want {
			t.Errorf("%s: %s, not %s", tc.command, got, tc.want)
		}
	}
}

// A pattern an arg operation might not catch, or catches no more strictly,
// still decides: only one it always tightens is refused at launch.
func TestAPatternAnArgOperationDoesNotAlwaysTightenIsAccepted(t *testing.T) {
	r := route(t, config(), `{"allow": ["grep -n TODO /srv/app", "* -r x", "grep * /srv/app"], "ask": ["grep -r **"]}`)
	for _, tc := range []struct{ command, want string }{
		{"grep -n TODO /srv/app", "allow"},
		{"ls -r x", "allow"},
		{"grep -r x", "ask"},
		{"grep -rn /srv/app", "ask"},
		{"grep TODO /srv/app", "allow"},
	} {
		if got := decide(r, tc.command); got != tc.want {
			t.Errorf("%s: %s, not %s", tc.command, got, tc.want)
		}
	}
	if r := route(t, config(), `{"allow": ["search-recursive", "grep -r TODO /srv/app"]}`); decide(r, "grep -r TODO /srv/app") != "allow" {
		t.Error("a pattern an allowed operation no longer tightens is not allowed")
	}
}

// A CATEGORY IS A TOPIC: allowing one allows its reads and writes, but
// none of what it guards, so that a project after more searching does not
// get find -exec with it; only an id allows a guarded operation, and a
// category asked or refused is all of it.
func TestAllowingACategoryAllowsNoneOfItsGuardedOperations(t *testing.T) {
	r := route(t, config(), `{"allow": ["category:search", "category:read", "category:packages", "category:files", "category:network"]}`)
	for _, tc := range []struct{ command, want string }{
		{"grep -r x /srv", "allow"},
		{"find / -fprint /srv/x", "allow"},
		{"diff -r a b", "allow"},
		{"cp a b", "allow"},
		{"apt install nginx", "allow"},
		{"find / -maxdepth 0 -exec sh -c id ';'", "refuse"},
		{"find . -delete", "refuse"},
		{"less +G x", "refuse"},
		{"less -k keys x", "refuse"},
		{"sort --compress-program=sh x", "refuse"},
		{"apt-get -o DPkg::Pre-Invoke::=id install nginx", "refuse"},
		{"dpkg -l --pre-invoke=id", "refuse"},
		{"apt remove nginx", "refuse"},
		{"rm x", "refuse"},
		{"systemctl -H other status nginx", "refuse"},
	} {
		if got := decide(r, tc.command); got != tc.want {
			t.Errorf("%s: %s, not %s", tc.command, got, tc.want)
		}
	}
	if r := route(t, config(), `{"allow": ["find-run"]}`); decide(r, "find . -exec id ';'") != "allow" {
		t.Error("a guarded operation's id does not allow it")
	}
	if r := route(t, config(), `{"ask": ["category:secrets"]}`); decide(r, "cat .env") != "ask" {
		t.Error("asking about the secrets category is not all of it")
	}
	c := config()
	c.Tiers["trusted"] = Tier{Writes: "allow", Guarded: "allow", Unmatched: "ask"}
	if r := route(t, c, `{"refuse": ["category:search"], "ask": ["category:files"]}`); decide(r, "find . -exec id ';'") != "refuse" || decide(r, "rm x") != "ask" {
		t.Error("a category refused or asked is not all of it")
	}
}

// UNMATCHED: the host's before the tier's. "allow" is a rule for every
// readable command, which the catalogue's more literal ones come before,
// and frisket refuses what it cannot read.
func TestUnmatchedIsTheHostsThenTheTiers(t *testing.T) {
	if r := route(t, config(), `{"unmatched": "refuse"}`); r.Unmatched != "refuse" || decide(r, "awk x") != "refuse" {
		t.Errorf("the host's unmatched is not the route's: %q", r.Unmatched)
	}
	r := route(t, config(), `{"unmatched": "allow"}`)
	if e, ok := rule(r, "**", ""); !ok || outcome(e) != "allow" || r.Unmatched != "refuse" {
		t.Errorf("unmatched allow is not a catch-all with what cannot be read refused: %+v %q", e, r.Unmatched)
	}
	for _, tc := range []struct{ command, want string }{
		{"awk x", "allow"}, {"rm x", "refuse"}, {"systemctl restart x", "ask"}, {"ls $(id)", "refuse"}, {"cat .ssh/x", "refuse"},
	} {
		if got := decide(r, tc.command); got != tc.want {
			t.Errorf("%s: %s, not %s", tc.command, got, tc.want)
		}
	}
	c := config()
	c.Tiers["trusted"] = Tier{Writes: "ask", Guarded: "refuse", Unmatched: "refuse"}
	if r := route(t, c, ""); r.Unmatched != "refuse" {
		t.Errorf("the tier's unmatched is not the route's: %q", r.Unmatched)
	}
	if r := route(t, c, `{"unmatched": "ask"}`); r.Unmatched != "ask" {
		t.Errorf("the host's unmatched is not before the tier's: %q", r.Unmatched)
	}
}

func TestWhatPrepareRefuses(t *testing.T) {
	refuseAll := config()
	refuseAll.Tiers["trusted"] = Tier{Writes: "refuse", Guarded: "refuse", Unmatched: "refuse"}
	neither, both := config(), config()
	neither.Agent = ""
	both.KeyFile = "/k"
	badTier := config()
	badTier.Tiers["trusted"] = Tier{Writes: "maybe", Guarded: "refuse", Unmatched: "ask"}
	unsafeEnv := config()
	unsafeEnv.Tiers["trusted"] = Tier{Writes: "ask", Guarded: "refuse", Unmatched: "ask", Env: []string{"LANG", "P*"}}
	noCatalogue := config()
	noCatalogue.Catalogue = "/nonexistent"
	for _, tc := range []struct {
		name    string
		c       Config
		binding string
		said    string
	}{
		{"an id the catalogue does not have", config(), binding(t, `{"allow": ["restart-everything"]}`), `"restart-everything" is no operation`},
		{"a category it does not have", config(), binding(t, `{"allow": ["category:fun"]}`), "category:fun is no category"},
		{"a route that refuses everything", refuseAll, binding(t, `{"refuse": ["category:navigate", "category:read", "category:search", "category:status", "category:processes", "category:logs", "category:services", "category:network", "category:packages", "category:containers"]}`), "every command is refused"},
		{"no credential", neither, binding(t, ""), "has neither"},
		{"two credentials", both, binding(t, ""), "has both"},
		{"a tier's answer that is none", badTier, binding(t, ""), `writes is "maybe"`},
		{"no catalogue", noCatalogue, binding(t, ""), "/nonexistent"},
		{"an env name that changes what runs", unsafeEnv, binding(t, ""), `trusted's env[1] "P*" names PATH`},
		{"a key the binding does not know", config(), `{"hosts": {}, "extra": 1}`, "unknown field"},
		{"a bad binding", config(), binding(t, `{"address": "server.lan"}`), "apps.ssh.hosts.server.address"},
		{"an allow a stricter catalogue pattern ties", config(), binding(t, `{"allow": ["systemctl restart *"]}`), `apps.ssh.hosts.server: allow "systemctl restart *" is as literal as the catalogue's "systemctl restart **" (service-restart)`},
		{"an allow the project's own refusal ties", config(), binding(t, `{"refuse": ["systemctl restart **"], "allow": ["systemctl restart *"]}`), `apps.ssh.hosts.server: allow "systemctl restart *" is as literal as the project's own refuse "systemctl restart **", which is stricter, and so decides every command both match: drop one, or make the allow more literal`},
		{"an ask a refusing catalogue pattern ties", config(), binding(t, `{"ask": ["rm * *"]}`), `"rm **" (remove)`},
		{"an allow of a category all guarded", config(), binding(t, `{"allow": ["category:secrets"]}`), "allow category:secrets allows nothing"},
		{"an allow of another", config(), binding(t, `{"allow": ["category:admin"]}`), "allow category:admin allows nothing"},
		{"an allow an arg operation asks about", config(), binding(t, `{"allow": ["grep -r TODO /srv/app"]}`), `allow "grep -r TODO /srv/app" has an argument the catalogue's search-recursive (-*r*) always makes ask, which a pattern never lifts: allow search-recursive`},
		{"an allow open-ended", config(), binding(t, `{"allow": ["grep -r **"]}`), "search-recursive"},
		{"an allow of a clock set", config(), binding(t, `{"allow": ["date 2026-01-01"]}`), "date-set"},
		{"an allow of an image root", config(), binding(t, `{"allow": ["systemctl --root=/mnt status x"]}`), "has an argument"},
		{"an allow of a find delete", config(), binding(t, `{"allow": ["find * -delete"]}`), "find-delete"},
		{"an allow of a power target", config(), binding(t, `{"allow": ["systemctl start reboot.target"]}`), "power-target"},
		{"an allow of lspci -H", config(), binding(t, `{"allow": ["lspci -H **"]}`), "hardware-direct"},
		{"an allow of a secret any command reads", config(), binding(t, `{"allow": ["cat /etc/ssh/ssh_host_ed25519_key.pub"]}`), "secret-ssh"},
		{"an ask of a secret", config(), binding(t, `{"ask": ["cat * .env"]}`), `ask "cat * .env" has an argument the catalogue's secret-environment`},
	} {
		_, _, err := prepare(t, tc.c, "trusted", tc.binding)
		if err == nil || !strings.Contains(err.Error(), tc.said) || !strings.HasPrefix(err.Error(), "/w: ssh: ") {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestATierWithoutSSHSaysSo(t *testing.T) {
	p, said, err := prepare(t, config(), "strict", binding(t, ""))
	if err != nil || len(p.SSH) != 0 {
		t.Fatalf("%v %+v", err, p)
	}
	if !strings.Contains(said, "/w: ssh ignored: strict has no ssh") {
		t.Errorf("it was not said: %q", said)
	}
}

func TestAConfigWithAKeyItDoesNotKnowIsRefused(t *testing.T) {
	if _, err := LoadConfig([]byte(`{"tiers": {}, "catalogue": "/c", "agnet": "/a"}`)); err == nil {
		t.Error("a misspelt key was loaded")
	}
	if c, err := LoadConfig([]byte(`{"tiers": {"t": {"writes": "ask", "guarded": "refuse", "unmatched": "ask"}}, "catalogue": "/c", "agent": "/a"}`)); err != nil || c.Agent != "/a" {
		t.Errorf("%v %+v", err, c)
	}
}

// overlap and covers put a question about every command to frisket as one
// command made to answer it. So each is what trying every command says:
// here, every command of up to four words, of the patterns' own literals
// and a word neither has.
func TestOverlapAndCoversAreWhatEveryCommandSays(t *testing.T) {
	word := rapid.SampledFrom([]string{"a", "b", "*"})
	pattern := rapid.Custom(func(t *rapid.T) string {
		ws := rapid.SliceOfN(word, 1, 3).Draw(t, "words")
		if rapid.Bool().Draw(t, "tail") {
			ws = append(ws, "**")
		}
		return strings.Join(ws, " ")
	})
	var commands [][]string
	var grow func([]string)
	grow = func(c []string) {
		if len(c) > 0 {
			commands = append(commands, c)
		}
		if len(c) < 4 {
			for _, w := range []string{"a", "b", "c"} {
				grow(append(slices.Clone(c), w))
			}
		}
	}
	grow(nil)
	m := matcher{}
	rapid.Check(t, func(t *rapid.T) {
		p, q := pattern.Draw(t, "p"), pattern.Draw(t, "q")
		both, all := false, true
		for _, c := range commands {
			mp, mq := m.matches(p, c), m.matches(q, c)
			both = both || mp && mq
			all = all && (!mq || mp)
		}
		if got := m.overlap(p, q); got != both {
			t.Fatalf("overlap(%q, %q) is %v, and every command says %v", p, q, got, both)
		}
		if got := m.covers(p, q); got != all {
			t.Fatalf("covers(%q, %q) is %v, and every command says %v", p, q, got, all)
		}
	})
}
