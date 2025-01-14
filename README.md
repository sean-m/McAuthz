# McAuthz
A library that allows using policy based rules for authorization in asp.net core. 

## Kinds of Authorization
Web api requests can be evaluated by policy in two ways: by principal and http method (GET, POST, etc)
or by principal and resource type. 
```
                       [ Authorization Middleware ]    [            Endpoint Middleware           ]
__________             ____________________________    ______________    __________________________
|        |             |   Authorization Policy   |    | Controller |    | Resource Authorization |
| Client | Request  -> | Inspect: Identity/Method | -> |            | -> |                        |
|        | Response <- |                          | <- |            | <- |    Inspect objects     |
----------             ----------------------------    --------------    --------------------------
                       [     Request Policies     ]    [             Resource Policies            ]
```

### Resource Authorization
