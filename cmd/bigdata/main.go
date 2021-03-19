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
      			"address": {
        			"type": "ip"
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
	Value    string `json:"value"`
	Address  string `json:"address,omitempty"`
}

func main() {
	var index,file string
	
	flag.StringVar(&file,"file","2021-02-27-1614388801-fdns_mx.json.gz","")
	flag.StringVar(&index, "index", "sonar2", "")
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

	file, err := os.Open(file)
	if err != nil {
		log.Fatalf("open %s", err)
	}

	reader, err := gzip.NewReader(file)
	if err != nil {
		log.Fatalf("new reader %s", err)
	}

	dec := json.NewDecoder(reader)
	n := 0
	bulk := client.Bulk()
	// while the array contains values
	for dec.More() {
		var m Sonar
		// decode an array value (Message)
		err := dec.Decode(&m)
		if err != nil {
			log.Fatal(err)
		}
		n += 1
		switch m.Type {
		case "mx":
			values := strings.Split(m.Value, " ")
			priority,err := strconv.ParseInt(values[0],10,32)
			if err != nil {
				log.Printf("mx: parseInt %s",err)
				continue
			}
			m.Priority = int(priority)
			m.Value = values[1]
		}

		indexReq := elastic.NewBulkIndexRequest().OpType("create").Index(index).Id(strconv.Itoa(n)).Type("_doc").Doc(m)
		bulk.Add(indexReq)

		if bulk.NumberOfActions() == 1000 {
			_, err = bulk.Do(ctx)
			if err != nil {
				log.Fatalf("bulk %s", err)
			}
			bulk = client.Bulk()
		}
	}
}
