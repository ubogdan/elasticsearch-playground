package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/olivere/elastic/v7"
)

/*
	"name":{
		"type":"text",
        "analyzer": "english",
	},
*/

const mapping = `
{
	"settings":{
		"number_of_shards": 1,
		"number_of_replicas": 0
	},
	"mappings":{
            "dynamic": "strict",
			"properties":{
				"name":{
					"type":"keyword"
				},
				"type":{
					"type":"keyword"
				},
				"priority": {
					"type":"short"
				},				
				"weight": {
					"type":"short"
				},
				"port": {
					"type":"short"
				},
				"value":{
					"type":"keyword"
				},
				"address":{
					"type":"ip"
				}
			}
	}
}`

type Sonar struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Priority int    `json:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty"`
	Port     int    `json:"port,omitempty"`
	Value    string `json:"value,omitempty"`
	Address  string `json:"address,omitempty"`
}

func main() {
	var index, filename string
	var batchSize int

	flag.IntVar(&batchSize, "batch-size", 10000, "")
	flag.StringVar(&filename, "file", "2021-02-26-1614298129-fdns_any.json.gz", "")
	flag.StringVar(&index, "index", "sonar", "")
	flag.Parse()

	// Starting with elastic.v5, you must pass a context to execute each service
	ctx := context.Background()

	// Obtain a client and connect to the default Elasticsearch installation
	// on 127.0.0.1:9200. Of course you can configure your client to connect
	// to other hosts and configure it in various other ways.
	client, err := elastic.NewClient(
		elastic.SetURL("http://127.0.0.1:9200"),
		//elastic.SetBasicAuth(c.Username, c.Password),
		elastic.SetSniff(false),
		elastic.SetHealthcheck(false),
	)
	if err != nil {
		// Handle error
		panic(err)
	}

	// Use the IndexExists service to check if a specified index exists.
	exists, err := client.IndexExists(index).Do(ctx)
	if err != nil {
		// Handle error
		panic(err)
	}
	if !exists {
		log.Printf("Creating index")
		// Create a new index.
		createIndex, err := client.CreateIndex(index).BodyString(mapping).Do(ctx)
		if err != nil {
			// Handle error
			panic(err)
		}
		if !createIndex.Acknowledged {
			// Not acknowledged
		}
	}

	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("open %s", err)
	}

	reader, err := gzip.NewReader(file)
	if err != nil {
		log.Fatalf("new reader %s", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	recv := make(chan Sonar, batchSize)
	go func() {
		bulk := client.Bulk()
		for {
			m, isOpen := <-recv

			bulk.Add(elastic.NewBulkIndexRequest().OpType("index").Index(index).Type("_doc").Doc(m))

			if bulk.NumberOfActions() == batchSize || !isOpen {
				_, err = bulk.Do(ctx)
				if err != nil {
					log.Fatalf("bulk %s", err)
				}
				if !isOpen {
					log.Printf("Last chunk processed ...")
					wg.Done()
					return
				}

				bulk = client.Bulk()
			}
		}
	}()

	log.Printf("Reading stream")
	dec := json.NewDecoder(reader)
	// while the array contains values
	for dec.More() {
		var m Sonar
		// decode an array value (Message)
		err := dec.Decode(&m)
		if err != nil {
			log.Fatal(err)
		}
		switch m.Type {
		case "a", "aaaa":
			m.Address, m.Value = m.Value, ""

		case "ns", "ptr", "soa", "cname", "srv", "txt":
		case "mx":
			values := strings.Split(m.Value, " ")
			priority, err := strconv.ParseInt(values[0], 10, 32)
			if err != nil {
				log.Printf("mx: parseInt %s", err)
				continue
			}
			m.Priority = int(priority)
			m.Value = values[1]

		// Intentionally skipped
		default:
			// "hinfo", "rsig", "rrsig", "ds", "cds", "caa", "wks", "dnskey", "cdnskey", "spf", "tlsa", "nsec3param", "sshfp", "any":
			continue
		}

		// Skip empty records
		if m.Value == "" && m.Address == "" {
			continue
		}

		recv <- m
	}

	close(recv)
	log.Printf("waiting for insert thread to finish")
	wg.Wait()
}
