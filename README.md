# !!! Notice: purpose of this repo is education.

# OAuth2 protocol

### Start authorization server

Go to authorization-server folder

```sh
$ flask --app wsgi:app db upgrade
$ flask --app wsgi:app --debug run
```

### Start client server

Go to client folder

```sh
$ python app.py
```
