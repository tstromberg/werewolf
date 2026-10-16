// Solr's shell launcher normally prepares its home. Do that once, as Solr's
// unprivileged user, without changing an existing home's configuration.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if err := setup(); err != nil {
		fmt.Fprintf(os.Stderr, "solr-setup: %s\n", err)
		os.Exit(1)
	}
}

func setup() error {
	const home = "/data/svc/solr/home"
	if err := os.MkdirAll(home, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(home, "configsets")); os.IsNotExist(err) {
		tmp, err := os.MkdirTemp(home, ".configsets-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		if err := os.CopyFS(tmp, os.DirFS("/usr/lib/solr/server/solr/configsets")); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(home, "configsets")); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for _, name := range []string{"solr.xml", "zoo.cfg"} {
		target := filepath.Join(home, name)
		if _, err := os.Lstat(target); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		b, err := os.ReadFile(filepath.Join("/usr/lib/solr/server/solr", name))
		if os.IsNotExist(err) && name == "zoo.cfg" {
			continue
		}
		if err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(b)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
