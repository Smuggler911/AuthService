<p>"POST" http://localhost:"PORT"/login</p>

```json
    "username":"",
     "password":""
```
access_token находится в хедере
refresh_token хранится в httpOnly cookie

<p>"POST" http://localhost:"PORT"/update-token</p>
обновление аксес токена рефреш токеном