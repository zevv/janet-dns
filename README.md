
## Introduction

This is a proof-of-concept async DNS resolver library for the Janet programming
language. This code is not at all production ready, as it only implements the
happy path and has virtually no error handling.

## Description

Address resolution is a complicated task that is usually performed by the libc
standard library using `getaddrinfo()` or similar calls. The Janet standard
library also uses this call for resolving when calling `net/address`; this can
be problematic because `getaddrinfo()` can potentially block for several
seconds, effectively blocking the current Janet thread and it's event loop as
well.

This library implements a very simply DNS resolver that does not rely on the
libc standard library functions; instead it communicates directly with DNS
servers to perform the lookup, allowing for proper async behavior that will not
block the event loop.

Note that the resolving behavior of this library is by no means standard and
might differ from the underlying libc implementation; also, it will only use
DNS for resolution and does not implement any other source like a local hosts
file.


## Example

```janet
(import ./resolver)

# Create resolver instance

(def res (resolver/new "8.8.4.4"))

# Call the :resolve method to perform a DNS lookup

(defn test[]
  (ev/sleep 0.1)
  (pp (:resolve res "nyt.com"))
  (ev/sleep 0.1)
  (pp (:resolve res "google.com" :AAAA)))


(ev/call test)
```

## TODO and Open questions

- Improve timeout and error handling
- Acquire DNS server IPs from system resolver configuration
- Cache resceived answers with proper time-to-live
- Implement TCP/53
- Primary/secondary server fallback

