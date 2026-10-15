// Allow the separate nginx group to read generated HTTP fragments and TLS
// files. Core's private data root still excludes every other service.
process.umask(0o027)
