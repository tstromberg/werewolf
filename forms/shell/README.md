# Shell

[mksh](https://github.com/MirBSD/mksh), the MirBSD Korn Shell, installed as
`/bin/mksh` and `/bin/sh`. This [form](form.yaml) supplies a shell for other
forms to include:

```yaml
base: prod
with: [shell]

weaknesses:
  programs-no-shell: mksh runs the application's shell commands
```

The form adds no listener, login service or general permission for services
to execute a shell. A service that needs one declares it in `run`.
Include individual utility packages when needed; mksh supplies shell
builtins, not BusyBox's applet collection. SSH forms include this form
and use mksh for operator logins.

`sh-shim` remains available for services that only need to launch one
declared command. Its `allow: [sh]` grant never authorizes mksh.

See [image availability](../../docs/forms-catalog.md#images-and-downloads)
before choosing a deployment command. Adding this form changes an image;
automatic signed A/B updates require a published image for that composition
or an update channel signed with your own keys.
