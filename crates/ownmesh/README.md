# ownmesh

OwnMesh command-line interface.

## Command tree

Full registration of specification §16.2 commands (login, device, session, approval, transfer, doctor, …).  
Most bodies are stubs until later chapters; `status` and `config validate` are live.

```bash
ownmesh --help
ownmesh status
ownmesh config validate
```

HTTP/OAuth dependencies (`reqwest`, `oauth2`, …) are pre-declared for chapter 5 work.
