# cloud-metadata(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

cloud-metadata — obtain boot configuration and account updates from cloud metadata

## SYNOPSIS

**cloud-metadata** [**once**]

## DESCRIPTION

The **cloud-metadata** utility fetches a base64-encoded Werewolf configuration archive
from GCP, AWS, Hetzner or Azure instance user data. With **once**, it validates and
rewrites the archive for init(8). It does not execute cloud-init scripts.

Without arguments, it checks cloud configuration each minute and reconciles account
changes. On machines without cloud configuration, the service stays down.

The network fetcher runs unprivileged as _cloud. Separate processes validate
configuration and publish accounts. The archive given to init contains only validated
plain files; network input does not select arbitrary privileged writes.

## FILES

- `/run/werewolf/cloud/config.tar`

  Rewritten configuration archive from a one-shot fetch.

## EXIT STATUS

In one-shot mode, unknown clouds and data that is not Werewolf configuration produce
status 0 without writing an archive. Errors produce status 1.

## SEE ALSO

init(8)
