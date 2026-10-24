package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for path, text := range map[string]string{"example/recipe.yaml": "package: example\n", "example/café<.patch": "patch\n", "example/a.patch": "patch\n", "example/a/nested.patch": "nested\n", "tools.lock.json": "{}\n", "scripts/build.py": "# build\n", "scripts/common.py": "# common\n"} {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func published(name, inputs string) manifest {
	m := manifest{Format: "werewolf-package-manifest/1", Context: name, Inputs: inputs, Names: []string{"example", "example-web"}, Version: "1.0-r2", Architectures: map[string]map[string]string{}}
	for _, arch := range []string{"aarch64", "x86_64"} {
		m.Architectures[arch] = map[string]string{"APKINDEX.tar.gz": strings.Repeat("a", 64)}
		for _, name := range m.Names {
			m.Architectures[arch][name+"-"+m.Version+".apk"] = strings.Repeat("b", 64)
		}
	}
	return m
}

func signed(t *testing.T, key *rsa.PrivateKey, m manifest) []byte {
	t.Helper()
	payload := canonical(m)
	h := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"format": "werewolf-package-release/1", "payload": payload, "signature": signature})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPromotionRequiresEveryPublishedInputAndArchitecture(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range []string{"none", "inputs", "context", "format", "arm64", "subpackage", "index", "signature", "missing", "late-failure"} {
		t.Run(problem, func(t *testing.T) {
			root := fixture(t)
			_, inputs, err := identities(root, []string{"example"})
			if err != nil {
				t.Fatal(err)
			}
			m := published("example", inputs["example"])
			switch problem {
			case "inputs":
				m.Inputs = strings.Repeat("a", 64)
			case "context":
				m.Context = "wrong"
			case "format":
				m.Format = "other"
			case "arm64":
				delete(m.Architectures, "aarch64")
			case "subpackage":
				delete(m.Architectures["aarch64"], "example-web-1.0-r2.apk")
			case "index":
				m.Architectures["x86_64"]["APKINDEX.tar.gz"] = "invalid"
			}
			data := signed(t, key, m)
			if problem == "signature" {
				data = bytesReplace(data, `"signature":"`, `"signature":"AAAA`)
			}
			l := lock{Format: "werewolf-package-sources/1", Sources: []source{{Name: "packages", Contexts: []string{"example"}, Ref: strings.Repeat("a", 40), SHA256: "old"}, {Name: "hardened-packages", Ref: "untouched"}}}
			if problem == "late-failure" {
				if err := os.Mkdir(filepath.Join(root, "second"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "second/recipe.yaml"), []byte("second"), 0o644); err != nil {
					t.Fatal(err)
				}
				l.Sources[0].Contexts = append(l.Sources[0].Contexts, "second")
			}
			before := string(canonical(l))
			get := func(_ context.Context, name string) ([]byte, error) {
				if problem == "missing" || name == "second" {
					return nil, fmt.Errorf("not published")
				}
				return data, nil
			}
			changed, err := promote(context.Background(), &l, root, strings.Repeat("b", 40), &key.PublicKey, get)
			if problem != "none" {
				if err == nil || changed || string(canonical(l)) != before {
					t.Fatalf("partial promotion: %+v %v %v", l, changed, err)
				}
				return
			}
			if err != nil || !changed || l.Sources[0].Ref != strings.Repeat("b", 40) || l.Sources[1].Ref != "untouched" {
				t.Fatalf("%+v %v %v", l, changed, err)
			}
			changed, err = promote(context.Background(), &l, root, strings.Repeat("c", 40), &key.PublicKey, get)
			if err != nil || changed || l.Sources[0].Ref != strings.Repeat("b", 40) {
				t.Fatal("unchanged source churned", changed, err)
			}
		})
	}
}

func bytesReplace(data []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(data), old, replacement, 1))
}

func TestDigestCompatibilityWithPythonAndInputChanges(t *testing.T) {
	root := fixture(t)
	consumer, inputs, err := identities(root, []string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	script := `import hashlib,importlib.machinery,importlib.util,pathlib,sys
sys.dont_write_bytecode=True
def load(name,path):
 loader=importlib.machinery.SourceFileLoader(name,path)
 spec=importlib.util.spec_from_loader(name,loader)
 mod=importlib.util.module_from_spec(spec);loader.exec_module(mod);return mod
source=load('source','../checkout-packages')
root=pathlib.Path(sys.argv[1]);print(source.digest(root,['example']))
# Publisher's input_digest encoding and order.
import json
paths=list((root/'example').rglob('*'))+[root/'tools.lock.json',root/'scripts/build.py',root/'scripts/common.py']
records=[dict(path=str(p.relative_to(root)),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),mode=p.stat().st_mode&0o7777) for p in sorted(paths) if p.is_file()]
print(hashlib.sha256((json.dumps(records,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest())
`
	out, err := exec.Command("python3", "-c", script, root).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if string(out) != consumer+"\n"+inputs["example"]+"\n" {
		t.Fatalf("digest mismatch:\n%s\n%s\n%s", out, consumer, inputs["example"])
	}
	if err := os.Chmod(filepath.Join(root, "example/recipe.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	nextConsumer, nextInputs, err := identities(root, []string{"example"})
	if err != nil || nextConsumer == consumer || nextInputs["example"] == inputs["example"] {
		t.Fatal("file mode ignored", err)
	}
	if err := os.Symlink("recipe.yaml", filepath.Join(root, "example/link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identities(root, []string{"example"}); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, names := range [][]string{{"../example"}, {"example", "example"}, {}} {
		if _, _, err := identities(root, names); err == nil {
			t.Fatal("invalid inventory accepted", names)
		}
	}
}

func TestCategoryMovesPreserveIdentitiesAndMetadataIsDescriptive(t *testing.T) {
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}

	root := fixture(t)
	write(filepath.Join(root, "example", "metadata.json"), `{"hardening":{"minimized":false}}`)
	before, inputs, err := identities(root, []string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "www"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "example"), filepath.Join(root, "www", "example")); err != nil {
		t.Fatal(err)
	}
	after, nextInputs, err := identities(root, []string{"example"})
	if err != nil || before != after || inputs["example"] != nextInputs["example"] {
		t.Fatal("category move changed package identities", err)
	}
	write(filepath.Join(root, "www", "example", "metadata.json"), `{"hardening":{"minimized":true}}`)
	described, describedInputs, err := identities(root, []string{"example"})
	if err != nil || described == after || describedInputs["example"] != nextInputs["example"] {
		t.Fatal("metadata must change reviewed source identity without rebuilding", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "net", "example"), 0755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "net", "example", "metadata.json"), `{}`)
	if _, _, err := identities(root, []string{"example"}); err == nil {
		t.Fatal("ambiguous categories accepted")
	}
}
