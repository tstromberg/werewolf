# debug-shell(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

debug-shell — provide a serial root shell on a developer image

## SYNOPSIS

**debug-shell**

## DESCRIPTION

The **debug-shell** service provides an unauthenticated root shell on the serial
console only when the image was built for development and booted with
`werewolf.debug=1`. Otherwise it takes itself down without opening a shell. The kernel
argument alone does not enable a shell on a production image.

Runit invokes the program through `/etc/sv/debug-shell/run`. Shell startup is reported
on the console. The shell inherits the machine's confinement and cannot remove it. The
service's shutdown handling avoids delaying stage 3 on an open console.

## FILES

- `/proc/cmdline`

  Developer-shell request.

- `/dev/console`

  Serial shell terminal.

## SEE ALSO

fence(8), posture(8), runit-stage(8)

## CAVEATS

Anyone with console access to an enabled developer image receives root.
