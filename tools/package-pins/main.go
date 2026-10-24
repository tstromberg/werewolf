// package-pins promotes source only after both native APK builds are published.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const publicFeed = "https://dist.werewolf-linux.org/apk/packages/"

var commitID = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var contextName = regexp.MustCompile(`^[a-z0-9][a-z0-9+_.-]*$`)

type source struct {
	Contexts   []string `json:"contexts"`
	Name       string   `json:"name"`
	Ref        string   `json:"ref"`
	Repository string   `json:"repository"`
	SHA256     string   `json:"sha256"`
}

type lock struct {
	Format  string   `json:"format"`
	Sources []source `json:"sources"`
}

// canonical matches the Python publisher and checkout helper's JSON encoding.
func canonical(value any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		panic(err)
	}
	var out strings.Builder
	for _, r := range b.String() {
		if r <= 127 {
			out.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&out, `\u%04x`, u)
		}
	}
	return []byte(out.String())
}

func sum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// pathlib sorts path components, so a/x sorts before a.patch.
func sortPaths(paths []string) {
	sort.Slice(paths, func(i, j int) bool {
		return slices.Compare(strings.Split(filepath.ToSlash(paths[i]), "/"), strings.Split(filepath.ToSlash(paths[j]), "/")) < 0
	})
}

func files(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular package input: %s", path)
		}
		paths = append(paths, path)
		return nil
	})
	sortPaths(paths)
	return paths, err
}

func record(root, path string) (map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("non-regular package input: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	mode := uint32(info.Mode().Perm())
	for bit, unix := range map[fs.FileMode]uint32{fs.ModeSetuid: 04000, fs.ModeSetgid: 02000, fs.ModeSticky: 01000} {
		if info.Mode()&bit != 0 {
			mode |= unix
		}
	}
	return map[string]any{"path": filepath.ToSlash(rel), "sha256": hex.EncodeToString(h.Sum(nil)), "mode": mode}, nil
}

func contextDir(root, name string) (string, error) {
	paths, err := filepath.Glob(filepath.Join(root, "*", name, "metadata.json"))
	if err != nil {
		return "", err
	}
	flat := filepath.Join(root, name)
	info, flatErr := os.Lstat(flat)
	if flatErr == nil && info.IsDir() && len(paths) == 0 {
		return flat, nil
	}
	if os.IsNotExist(flatErr) && len(paths) == 1 {
		return filepath.Dir(paths[0]), nil
	}
	return "", fmt.Errorf("missing or ambiguous context: %s", name)
}

func identities(root string, contexts []string) (string, map[string]string, error) {
	contexts = append([]string(nil), contexts...)
	sort.Strings(contexts)
	if len(contexts) == 0 {
		return "", nil, errors.New("empty package inventory")
	}
	all := sha256.New()
	inputs := map[string]string{}
	for _, name := range contexts {
		if !contextName.MatchString(name) || name == "." || name == ".." || inputs[name] != "" {
			return "", nil, fmt.Errorf("invalid or duplicate context: %s", name)
		}
		dir, err := contextDir(root, name)
		if err != nil {
			return "", nil, err
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return "", nil, err
		}
		if !info.IsDir() {
			return "", nil, fmt.Errorf("missing context directory: %s", name)
		}
		paths, err := files(dir)
		if err != nil {
			return "", nil, err
		}
		if len(paths) == 0 {
			return "", nil, fmt.Errorf("empty context: %s", name)
		}
		for _, path := range paths {
			r, err := record(dir, path)
			if err != nil {
				return "", nil, err
			}
			r["context"] = name
			all.Write(canonical(r))
		}
		buildPaths := []string{}
		for _, path := range paths {
			if path != filepath.Join(dir, "metadata.json") {
				buildPaths = append(buildPaths, path)
			}
		}
		paths = append(buildPaths, filepath.Join(root, "tools.lock.json"), filepath.Join(root, "scripts/build.py"), filepath.Join(root, "scripts/common.py"))
		catalog := filepath.Join(root, "scripts/catalog.py")
		if _, err := os.Lstat(catalog); err == nil {
			paths = append(paths, catalog)
		} else if !os.IsNotExist(err) {
			return "", nil, err
		}
		sortPaths(paths)
		records := []map[string]any{}
		for _, path := range paths {
			r, err := record(root, path)
			if err != nil {
				return "", nil, err
			}
			if rel, err := filepath.Rel(dir, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				r["path"] = filepath.ToSlash(filepath.Join(name, rel))
			}
			records = append(records, r)
		}
		sort.Slice(records, func(i, j int) bool {
			return slices.Compare(strings.Split(records[i]["path"].(string), "/"), strings.Split(records[j]["path"].(string), "/")) < 0
		})
		inputs[name] = sum(canonical(records))
	}
	return hex.EncodeToString(all.Sum(nil)), inputs, nil
}

type manifest struct {
	Format        string                       `json:"format"`
	Context       string                       `json:"context"`
	Inputs        string                       `json:"inputs"`
	Names         []string                     `json:"names"`
	Version       string                       `json:"version"`
	Architectures map[string]map[string]string `json:"architectures"`
}

func openManifest(data []byte, key *rsa.PublicKey) (manifest, error) {
	var envelope struct {
		Format             string
		Payload, Signature []byte
	}
	var m manifest
	if err := json.Unmarshal(data, &envelope); err != nil {
		return m, err
	}
	if envelope.Format != "werewolf-package-release/1" {
		return m, errors.New("unknown release envelope")
	}
	h := sha256.Sum256(envelope.Payload)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], envelope.Signature); err != nil {
		return m, fmt.Errorf("publication signature: %w", err)
	}
	if err := json.Unmarshal(envelope.Payload, &m); err != nil {
		return m, err
	}
	return m, nil
}

func verify(m manifest, name, inputs string) error {
	if m.Format != "werewolf-package-manifest/1" || m.Context != name || m.Inputs != inputs {
		return fmt.Errorf("%s: candidate inputs are not published", name)
	}
	if len(m.Names) == 0 || m.Version == "" || len(m.Architectures) != 2 {
		return fmt.Errorf("%s: incomplete package identity", name)
	}
	for _, arch := range []string{"aarch64", "x86_64"} {
		files := m.Architectures[arch]
		if len(files) != len(m.Names)+1 || !digestID.MatchString(files["APKINDEX.tar.gz"]) {
			return fmt.Errorf("%s: incomplete %s publication", name, arch)
		}
		seen := map[string]bool{}
		for _, pkg := range m.Names {
			if !contextName.MatchString(pkg) || seen[pkg] || !digestID.MatchString(files[pkg+"-"+m.Version+".apk"]) {
				return fmt.Errorf("%s: missing %s APK for %s", name, pkg, arch)
			}
			seen[pkg] = true
		}
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, address string) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("publication feed must use HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("publication %s: %s", address, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err == nil && len(data) > 4<<20 {
		err = errors.New("oversized publication record")
	}
	return data, err
}

func promote(ctx context.Context, l *lock, packages, ref string, key *rsa.PublicKey, get func(context.Context, string) ([]byte, error)) (bool, error) {
	if l.Format != "werewolf-package-sources/1" || !commitID.MatchString(ref) {
		return false, errors.New("invalid lock format or candidate commit")
	}
	var candidate *source
	for i := range l.Sources {
		if l.Sources[i].Name == "packages" {
			if candidate != nil {
				return false, errors.New("duplicate packages source")
			}
			candidate = &l.Sources[i]
		}
	}
	if candidate == nil {
		return false, errors.New("missing packages source")
	}
	digest, inputs, err := identities(packages, candidate.Contexts)
	if err != nil {
		return false, err
	}
	for _, name := range candidate.Contexts {
		data, err := get(ctx, name)
		if err != nil {
			return false, err
		}
		m, err := openManifest(data, key)
		if err != nil {
			return false, fmt.Errorf("%s: %w", name, err)
		}
		if err := verify(m, name, inputs[name]); err != nil {
			return false, err
		}
	}
	// Commits that change only documentation or automation need no consumer PR.
	if candidate.SHA256 == digest {
		return false, nil
	}
	candidate.Ref, candidate.SHA256 = ref, digest
	return true, nil
}

func run() error {
	root := flag.String("root", ".", "Werewolf checkout")
	packages := flag.String("packages", "../packages", "clean candidate package checkout")
	feed := flag.String("feed", publicFeed, "signed publication feed")
	write := flag.Bool("write", false, "replace the source lock after verification")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", *packages}, args...)...)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	status, err := git("status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	if status != "" {
		return errors.New("candidate checkout has uncommitted changes")
	}
	ref, err := git("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	path := filepath.Join(*root, "release/package-sources.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var l lock
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&l); err != nil {
		return err
	}
	trust, err := os.ReadFile(filepath.Join(*root, "release/application-packages.pub"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(trust)
	if block == nil {
		return errors.New("missing publication trust key")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok {
		return errors.New("publication trust key must be RSA")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" {
			return errors.New("unsafe publication redirect")
		}
		return nil
	}}
	changed, err := promote(ctx, &l, *packages, ref, key, func(ctx context.Context, name string) ([]byte, error) {
		return fetch(ctx, client, strings.TrimRight(*feed, "/")+"/contexts/"+name+"/current.json")
	})
	if err != nil {
		return err
	}
	if !changed {
		fmt.Println("package-pins: current")
		return nil
	}
	if *write {
		data, err := json.MarshalIndent(l, "", "  ")
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".package-pins-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(append(data, '\n')); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Chmod(0o644); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			return err
		}
	}
	fmt.Println("package-pins: published candidate", ref)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "package-pins:", err)
		os.Exit(1)
	}
}
