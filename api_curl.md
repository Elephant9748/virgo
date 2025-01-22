### GET
```
curl http://localhost:7000/ | jq "."
```
### POST
```
curl -d '{"username":"?", "pass":"?"}' -H "Content-Type: application/json" -X POST http://localhost:7000/ | jq "."
curl -d '{"username":"?", "pass":"?"}' -H "Content-Type: application/json" -X POST http://localhost:7000/acc/add | jq "."
```
### DELETE
```
curl -d '{"username":"?"}' -H "Content-Type: application/json" -X DELETE http://localhost:7000/ | jq "."
curl -d '{"username":"?"}' -H "Content-Type: application/json" -X DELETE http://localhost:7000/acc/del | jq "."
```
