


* `SELECT FROM sonar WHERE "value"= "deanx.netlify.com" AND "type": "cname"`
```sql
GET /sonar/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "value": "deanx.netlify.com" }}, 
        { "match": { "type": "cname" } }
      ]
    }
  }
}
```