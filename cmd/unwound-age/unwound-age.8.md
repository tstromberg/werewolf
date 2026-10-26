# unwound-age(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

unwound-age — maintain protected domain-age evidence for DNS policy

## SYNOPSIS

**unwound-age**

## DESCRIPTION

The **unwound-age** authority supplies domain-age evidence to unwound(8). init(8)
starts it before fence and synchronizes setup over an inherited descriptor. It has no
operator command interface.

Setup creates a private mount namespace and writable database view. Init covers the
database and socket directories with read-only binds in the main namespace before
permitting services to start. The authority then drops to _unwoundage.

A supervisor holds no database, restarts the writer and bounds fetch times. The writer
owns the database and resolver channel but opens no TCP connection and parses no
provider response. Separate confined fetch children retrieve evidence. At most four
fetches run concurrently, one per service, each with a ten-second deadline. When
durable data is unavailable, the authority uses temporary storage.

## SEE ALSO

fence(8), init(8), unwound(8)
