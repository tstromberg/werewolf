package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"testing"
)

func TestCacheConfigKeepsValidXMLAndExistingSettings(t *testing.T) {
	for _, input := range []string{
		`<config><query><filterCache size="512"/><documentCache class="solr.CaffeineCache" size="32"/></query></config>`,
		`<config><!-- preserve this --><queryResultCache initialSize="${cacheSize:512}" class="solr.FastLRUCache"/></config>`,
		`<config><query><cache name="perSegFilter" class="solr.CaffeineCache" size="10"/></query></config>`,
		`<config><query><cache name="perSegFilter" size="10" initialSize="0" autowarmCount="10" regenerator="solr.NoOpRegenerator"/></query></config>`,
		`<config><cache name="perSegFilter" class="org.apache.solr.search.CaffeineCache"/></config>`,
	} {
		output, err := cacheConfig([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		decoder := xml.NewDecoder(bytes.NewReader(output))
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local == "config" || start.Name.Local == "query" {
				continue
			}
			classes := 0
			for _, attr := range start.Attr {
				if attr.Name.Local == "class" {
					classes++
					if attr.Value != "solr.LRUCache" {
						t.Fatal(attr)
					}
				}
			}
			if classes != 1 {
				t.Fatal(string(output))
			}
		}
		if bytes.Contains([]byte(input), []byte("${cacheSize:512}")) && !bytes.Contains(output, []byte("${cacheSize:512}")) {
			t.Fatal(string(output))
		}
	}
	if _, err := cacheConfig([]byte(`<config><filterCache></config>`)); err == nil {
		t.Fatal("accepted malformed config")
	}
}

func TestCacheConfigPreservesOtherNamedCacheImplementations(t *testing.T) {
	input := []byte(`<config><cache name="custom" class="custom.SpecializedCache" size="10"/></config>`)
	output, err := cacheConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte(`class="custom.SpecializedCache"`)) || bytes.Contains(output, []byte("solr.LRUCache")) {
		t.Fatal(string(output))
	}
}
