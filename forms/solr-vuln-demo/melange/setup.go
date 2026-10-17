// Solr's shell launcher normally prepares its home. Do that once, as Solr's
// unprivileged user, without changing an existing home's configuration.
package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
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
		// Solr 8 defaults to Caffeine 2, whose implementation needs Unsafe.
		// Its supported LRU cache keeps query caching without native memory.
		err = filepath.WalkDir(tmp, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || entry.Name() != "solrconfig.xml" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			data, err = cacheConfig(data)
			if err != nil {
				return err
			}
			return os.WriteFile(path, data, 0600)
		})
		if err != nil {
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

// Preserve XML tokens, including placeholders and comments; replace rather than
// duplicate a cache's existing class attribute in either packaged configset.
func cacheConfig(data []byte) ([]byte, error) {
	var output bytes.Buffer
	decoder := xml.NewDecoder(bytes.NewReader(data))
	encoder := xml.NewEncoder(&output)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if start, ok := token.(xml.StartElement); ok {
			replace := false
			switch start.Name.Local {
			case "filterCache", "queryResultCache", "documentCache", "fieldValueCache":
				replace = true
			case "cache":
				// Named user caches (the default perSegFilter, for example)
				// default to Caffeine too, including when class is omitted.
				replace = true
				for _, attr := range start.Attr {
					if attr.Name.Local == "class" {
						replace = attr.Value == "solr.CaffeineCache" || attr.Value == "org.apache.solr.search.CaffeineCache"
					}
				}
			}
			if replace {
				attrs := make([]xml.Attr, 0, len(start.Attr)+1)
				for _, attr := range start.Attr {
					if attr.Name.Local != "class" {
						attrs = append(attrs, attr)
					}
				}
				start.Attr = append(attrs, xml.Attr{Name: xml.Name{Local: "class"}, Value: "solr.LRUCache"})
				token = start
			}
		}
		if err := encoder.EncodeToken(token); err != nil {
			return nil, err
		}
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
