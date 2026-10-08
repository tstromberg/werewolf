# MinIO

The `minio` form is `prod` with MinIO serving S3 from `/data/svc/minio`:
the backup target for `restic` and `rclone`, the object store for an
application.

| | |
| --- | --- |
| Listens | tcp/9000, the S3 API, plain HTTP behind `caddy` or the cloud's balancer |
| Sends | nothing: no KMS, notifications, replication or update check |
| Runs as | `minio` (uid 217), leashed |
| Keeps | the objects in `/data/svc/minio` |
| Config | `minio/root_user` and `minio/root_password`, read into its environment |

```sh
printf '%s' admin >config/minio/root_user
openssl rand -base64 24 | tr -d '\n' >config/minio/root_password
build/host/werewolf pack minio -o config.tar --config config
mc alias set store https://s3.example.com admin "$(cat config/minio/root_password)"
mc mb store/backups && mc admin user add store restic ...
```

The console is off (`MINIO_BROWSER=off`): the API is the interface and
`mc` its client. Nothing is anonymous until a bucket's policy says so.

## Checked

`make check-minio` runs [test/checks-minio](../test/checks-minio) with
`mc`, which the DEV build carries: the health endpoint answers; an
anonymous request is 403; a bucket is made and an object goes up and
comes back as it went, on `/data`; the object is 403 to anyone else;
nothing listens for a console; the credentials are root's files.
