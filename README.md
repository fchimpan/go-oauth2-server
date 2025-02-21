# go-oauth2-server

Only Authorization Code Grant is implemented.
reference: https://datatracker.ietf.org/doc/html/rfc6749

## Authorize Request

```
CLIENT_ID=client_id
CLIENT_SECRET=client_secret
REDIRECT_URI=http://localhost:8088/callback

curl "localhost:8088/authorize?response_type=code&redirect_uri=$REDIRECT_URI&state=xyz&client_id=$CLIENT_ID"
```

## Token Request

```
CODE=code
curl -X POST "localhost:8088/token" -d "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT_URI" -H "Authorization: Basic $(echo -n $CLIENT_ID:$CLIENT_SECRET | base64)"
```
