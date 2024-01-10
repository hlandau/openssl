Demo-Driven Design: Server API (DDD-SERVER)
===========================================

Table of Contents
-----------------

- [Demo-Driven Design: Server API (DDD-SERVER)](#demo-driven-design--server-api--ddd-server-)
  * [Table of Contents](#table-of-contents)
  * [Background](#background)
  * [Choosing representative demos](#choosing-representative-demos)
    + [Design Space](#design-space)
    + [Design Space Reduction](#design-space-reduction)
    + [Supplemental Demos](#supplemental-demos)
  * [Overview of Chosen Demos](#overview-of-chosen-demos)
  * [Discussions on the support of fork(2)](#discussions-on-the-support-of-fork-2-)
    + [Listener-based fork support](#listener-based-fork-support)
    + [Stateless fork support](#stateless-fork-support)
    + [Prefork support](#prefork-support)
  * [Discussions on the support of DTLS](#discussions-on-the-support-of-dtls)
  * [Comments on proposed changes](#comments-on-proposed-changes)

Background
----------

For the development of QUIC MVP, which provided client-side QUIC functionality
shipped in OpenSSL 3.2, a demo-driven design process was conducted to validate
proposed QUIC API designs, with the specific objective of minimising changes
needed to existing applications to start making use of QUIC. The proposed API
changes were validated with regard to this requirement by developing a set of
demos intended to be broadly representative of client-side TLS API usage
patterns and then specifying a QUIC API indirectly by modelling a set of
proposed minimally required changes to those demos to enable usage for QUIC.

We now repeat this process as part of validating our server API design.
Following the same process, we construct a set of demos which, taken together,
are expected to be broadly representative of the diversity of OpenSSL API usage
patterns on the server side, and then model proposed changes to adapt such
strawman applications to use with QUIC, again seeking to minimise the changes
needed and ensure foreseeable use cases are met.

Choosing representative demos
-----------------------------

### Design Space

In order to determine a set of demos which, taken together, can be considered
representative of the diversity of ways in which assorted server applications
are constructured, it is necessary to choose these demos strategically to
provide good coverage of the relevant aspects of the design space while
minimising combinatorial explosion.

As such, we begin with an exploration of the application design space with
regard to how the existing libssl APIs can be used by a server process. Firstly,
consider that the DDD process for the client-side API characterised applications
by two principal factors:

- **Design Axis A: Synchronicity.** Whether an application uses the libssl API
  in a synchronous (blocking) or asynchronous (non-blocking) manner.

- **Design Axis B: Network I/O Attachment Model.** How libssl is provided access
  to the network via a BIO (e.g. via a socket BIO or via a memory buffer BIO);
  whether an enhanced BIO to assist with connection establishment (e.g.
  BIO_s_connect) is used.

Both of these design axes remain relevant to server applications, with
significant variation expected. However, due to the inherently concurrent nature
of a server handling multiple incoming connections, there are additional
relevant design axes. In particular, the matter of a server's concurrency model
must be considered:

- **Design Axis C: Concurrency Model**. How a server manages concurrent
  processing of independent connections (and for QUIC, streams). Broadly
  speaking, server daemons adopt one of the following strategies:

  - **Fork.** This is the most traditional UNIX implementation model for a TCP
    server. A daemon calls `accept(3)` in a loop and calls `fork(3)` for each
    accepted connection to produce a child process which is dedicated to
    servicing that connection. The child process exits when the connection is
    closed.

  - **Prefork.** This is a variant on the fork model. A set number of child
    processes are forked using `fork(3)`, and each one calls `accept(3)` in a
    loop on the same socket. It can be more performant than the fork model
    because the same child process can be reused for multiple successive
    connections.

  - **Multithread.** One thread is spun up per client connection in a single
    process. This can also be combined with the Prefork approach to create
    a Multiprocess Multithread (MPMT) model.

  - **Async.** Multiple connections are serviced using a single thread using
    an event-based asynchronous I/O reactor. This strategy may be combined with
    the use of multiple threads or be single-threaded.

  Occasionally a **hybrid model** is seen in which two of these strategies are
  mixed. One example of this is Apache httpd 2.4's `mod_mpm_event`, which
  services idle connections in keepalive using an async-based model, but active
  connections using a multithread model. A given connection is migrated
  dynamically between these two processing models as needed.

There are also other design axes which were not considered during the
client-side DDD process but which are relevant to both client and servers,
though perhaps moreso to servers:

- **Design Axis D: Pollability.** Whether a network-side BIO is pollable
  (exposes a poll descriptor, e.g. a socket BIO) or non-pollable (e.g. a memory
  BIO).

- **Design Axis E: Addressing Mode.** Whether a network-side BIO provides
  and can handle addressing information or not.

Finally, we consider the number of independent connection listeners
a server might use concurrently:

- **Design Axis F: Listener Cardinality.** Whether a server accepts
  from multiple (e.g. TCP) sockets at a time or not.

### Design Space Reduction

Taking $a=|A|, b=|B|, ...$ where $|A|$ is the number of values admitted by that
design axis, the full design space exhibits $|τ|=abcdef$ points. We can take
$a=2$; $c=4$; $d=2$; $e=2$; $f=2$, so $|τ|=64b$. We can already see that this an
untenably large design space to independently validate all design points with a
demo, as with $b≥2$ at it would imply producing at least 128 different demos.

Before continuing, we can identify a few simplifications. Firstly, design axis C
is not independent of design axis A as the Async concurrency model implies an
asynchronous programming model, whereas all other points on this axis imply a
synchronous programming model. We therefore drop design axis A which was used in
the client-side DDD process, considering it to be fully subsumed into design
axis C.

Equally, design axes D and E are not fully independent of design axis B, as the
choice of point in axis B fully implies positions on axes D and E. In practice,
the *interesting* API differences which impinge on libssl design aspects are
captured by design axes D and E. We therefore discard design axis B. In
actuality, the two most significant points on axis B are using a socket directly
and using a memory buffer BIO, which we will capture anyway in axis D, as these
are the representative examples of pollable and non-pollable BIOs.

Thus our design space is now $|τ|=cdef$, or $|τ|=32$. This is still a large
number of demos to produce, so we now consider our strategic allocation of demos
to different combinations of design choices:

- Design axis F is of limited relevance because being able to accept connections
  from multiple listeners concurrently is a superset of the functionality of
  being able to accept connections from one listener concurrently. However,
  the single-listener case should be considered to ensure that usage in this
  case is as simple as can be for an application. We therefore model most demos
  using a multi-listener approach but with one or two demos exhibiting
  single-listener usage. This reduces our chosen set to 16 demos.

The remaining possible demos to be produced are as follows:

```text
FORK        POLLABLE        ADDRESSED
FORK        POLLABLE        UNADDRESSED
FORK        NON-POLLABLE    ADDRESSED
FORK        NON-POLLABLE    UNADDRESSED
PREFORK     POLLABLE        ADDRESSED
PREFORK     POLLABLE        UNADDRESSED
PREFORK     NON-POLLABLE    ADDRESSED
PREFORK     NON-POLLABLE    UNADDRESSED
MT          POLLABLE        ADDRESSED
MT          POLLABLE        UNADDRESSED
MT          NON-POLLABLE    ADDRESSED
MT          NON-POLLABLE    UNADDRESSED
ASYNC       POLLABLE        ADDRESSED
ASYNC       POLLABLE        UNADDRESSED
ASYNC       NON-POLLABLE    ADDRESSED
ASYNC       NON-POLLABLE    UNADDRESSED
```

Further reductions can now be identified. As previously established during the
design of the client-side QUIC API, we are unable to support synchronous
(blocking) operation unless we have a pollable network-side BIO. Some of the
above design points are therefore nonsensical and can be removed:

```text
FORK        POLLABLE        ADDRESSED
FORK        POLLABLE        UNADDRESSED
PREFORK     POLLABLE        ADDRESSED
PREFORK     POLLABLE        UNADDRESSED
MT          POLLABLE        ADDRESSED
MT          POLLABLE        UNADDRESSED
ASYNC       POLLABLE        ADDRESSED
ASYNC       POLLABLE        UNADDRESSED
ASYNC       NON-POLLABLE    ADDRESSED
ASYNC       NON-POLLABLE    UNADDRESSED
```

We now have reduced our set to 10 demos. Note that all of the synchronous
examples here use a pollable network BIO (e.g. a socket BIO), whereas the
asynchronous non-pollable example are likely to use a memory buffer BIO (e.g. a
`BIO_s_dgram_pair`). Thus the two most significantly distinct design points on
the subsumed design axis B are properly explored.

**Exploring design axis E (addressing mode).** Addressed mode relates to whether
a network-side BIO is addressing-aware. In other words, does the libssl QUIC
stack receive datagrams from a network BIO (which might after all be a custom
BIO or a memory buffer BIO) which come from an unspecified location without L4
addresses attached to them, or do the datagrams which come from a BIO have full
addressing information attached to them, allowing the QUIC stack to communicate
with different endpoints?

Addressed mode is preferred and will be a requirement for supporting connection
migration in the future. Unaddressed mode is essentially a compatibility
technology designed to make it easier for people using memory buffer BIOs to
adapt their applications to use QUIC, though it can also be used for testing.
Since a QUIC server intrinsically receives multiple connections on the same UDP
socket, unaddressed mode is not obviously applicable to QUIC. However, it is
actually possible to support unaddressed mode with QUIC if a network BIO is
constrained to only handling a single connection. In fact we already do this
with our internal non-compliant QUIC test server used in the test suite for 3.2;
the server accepts a connection from a single client and is then bound to that
client, and only that client, forever. This is at least one case in which we can
support unaddressed operation. Theoretically, an application could choose to
instantiate a separate memory buffer BIO and libssl QUIC server for each
incoming QUIC connection, by doing its own parsing and routing of QUIC packet
headers. This does not seem particularly useful in practice but may be useful in
test scenarios.

In practice we do not need to impose a hard rule such as “one connection per
unaddressed BIO”; rather, we can simply say that when an application uses an
unaddressed BIO, it is responsible for determining peer addresses for outgoing
datagrams. It is conceivable that some applications may wish to do their own
tracking of source addresses and handle the mapping of outgoing datagrams to
peer addresses accordingly.

In any case, our expectation is that the API design considerations around
addressing mode will be orthogonal to issues of concurrency and the
application-side programming model. Therefore, we model unaddressed operation in
only a single demo representing the most complex use case (non-pollable async):

```text
FORK        POLLABLE        ADDRESSED
PREFORK     POLLABLE        ADDRESSED
MT          POLLABLE        ADDRESSED
ASYNC       POLLABLE        ADDRESSED
ASYNC       NON-POLLABLE    ADDRESSED
ASYNC       NON-POLLABLE    UNADDRESSED
```

We have now reduced the set of demos to 6, which is comparable to the number of
demos which were developed during the client-side DDD process. We consider the
above set of points in the design space to be broadly representative of the
varied spectrum of server implementation approaches found in the wild. While not
all design points can be explored due to combinatorial explosion, the points
chosen have been chosen to maximally exercise potential API issues and identify
likely issues.

For example, as mentioned under the discussion of design point C, the Async
concurrency model can be used in a single-threaded or multi-threaded manner. We
make the async demos exhibit multi-threaded usage as we consider this to be a
superset of the single-threaded use case.

### Supplemental Demos

There is also a desire to have a unified libssl API in future with compelling
design for other protocols such as DTLS, etc., in addition to TLS and
QUIC. In order to capture this, an additional demo will be produced based on
research of existing usage of OpenSSL DTLS functionality.

DTLS can be used over either UDP or SCTP. The specification for DTLS over SCTP
renders the SCTP stream number for a data chunk largely meaningless and it is up
to the application to interpret this. As such, the API considerations for
existing code using DTLS over SCTP do not appear to be sufficiently distinct
from the existing usage of DTLS over UDP. The significant difference from the
SCTP API model for accessing multiple streams is its use of a multipoint-style
API, which is distinct from our object-oriented multistream API. This is
discussed further as a possible future API direction in the server API design
document, but we do not intend to support such an API in the initial release of
QUIC server support, so such API design aspects are not considered here.

Overview of Chosen Demos
------------------------

The following demos have been produced:

| Filename             | Concurrency       | Target    | Pollable?    | Addressed?  | Listener Cardinality |
|----------------------|-------------------|-----------|--------------|-------------|----------------------|
| fork                 | Fork              | POSIX     | Pollable     | Addressed   | Single Listener      |
| prefork              | Prefork           | POSIX     | Pollable     | Addressed   | Multiple Listener    |
| mt                   | Multithreaded     | libuv     | Pollable     | Addressed   | Multiple Listener    |
| async-pollable       | MT Isolated Async | libuv     | Pollable     | Addressed   | Multiple Listener    |
| async-nonpollable    | MT Isolated Async | libuv     | Non-pollable | Addressed   | Multiple Listener    |
| async-unaddressed    | MT Isolated Async | libuv     | Non-pollable | Unaddressed | Multiple Listener    |
| dtls                 | MT Isolated Async | libuv     | Pollable     | Addressed   | Multiple Listener    |

The pollable demos will use a `BIO_s_socket` (for TLS) or `BIO_s_datagram` (for
QUIC) and the non-pollable demos will use a memory buffer BIO (`BIO_s_bio` or
`BIO_s_dgram_pair`).

The async demos use `libuv` as a representative asynchronous I/O library. This
is a popular event-based I/O library, used amongst other things as the
foundation of Node.js, and successful integration of a proposed QUIC server API
on top of it is a positive and representative indicator of the adaptability of
other asynchronous server architectures to a proposed API.

Some of these demos (e.g. `fork`, `prefork`, `mt`) are designed for use on
POSIX/UNIX systems. The `fork`/`prefork` demos are obviously relevant only to
such systems. The `async` demos are portable due to use of `libuv`'s
platform-abstracting thread creation API. The `mt` demo is portable as,
similarly to the `async` demos, it uses uses `libuv` as a simple compatibility
layer for portable thread creation, but does not use its event loop
functionality.

“MT Isolated Async” is an event-based multi-threaded concurrency model in which
multiple separate worker threads process connections. Each connection has
affinity to a specific worker thread chosen when the connection is created. The
workers do not interact with one another in terms of connection scheduling
and are effectively isolated.

The `async` demos use non-blocking I/O at the application level, whereas the
`fork`, `prefork` and `mt` demos use blocking I/O at the application level.

The `async-unaddressed` demo will simply be a build option to
`async-nonpollable` as the code differences are likely to be very small.

As with the client-side DDD process, proposed changes to enable a demo server
application for QUIC are shown, guarded by `#ifdef USE_QUIC` guards.

Discussions on the support of fork(2)
-------------------------------------

Supporting fork() would be a complex feature with its own API implications. As
such, we do not propose to implement support for the fork or prefork concurrency
models at this time. Nonetheless, it is interesting to note that in principle,
implementation should be possible, albeit with some application-visible API
complications. Various possible approaches are discussed below.

### Listener-based fork support

Two of the demos chosen above use fork(); one before accepting a connection, and
one after. The use of a multi-process architecture creates difficulty with a
potential QUIC implementation and this is further compounded by the copying of
all of our internal state at the time the fork occurs.

Let us consider the trivial fork() model:

```c
{
    SSL *listener   = ...;
    SSL *conn       = NULL;
    pid_t pid;

    conn = SSL_accept_connection(listener, 0);
    if (conn == NULL)
        return;

    pid = fork();
    if (pid == 0)
        /* child */
        handle_conn(conn);
}
```

In this model we have a listener object with arbitrary amounts of internal
state, which for sake of example has been attached to a datagram BIO. Once the
QUIC stack identifies a new incoming connection, it creates a new object to
represent the connection and outputs it to the application when it calls
`SSL_accept_connection`. Then the entire process and the entire state of the
QUIC stack is copied.

There are two principal problems here:

1. There is conflicting and duplicated state.

2. There are now two processes trying to receive incoming datagrams from an
   incoming UDP socket.

Note that both processes sending on the same socket is *not* an issue.

While at first glance it may seem the use of a userspace QUIC implementation
with fork() poses insoluable challenges, in actuality both of these problems are
in principle solvable. API calls could be provided to allow an application to
notify the QUIC stack that forking is about to, or has, occurred. This rectifies
the first issue as the QUIC stack can then perform arbitrary corrections of its
state accordingly. (APIs such as `pthread_atfork` do exist for detecting this
explicitly, which OpenSSL used in the past but which has since ceased using. Any
usage of such an API should be strictly opt-in, and the use of an API explicitly
at the time an application calls fork() should probably be considered
preferred.)

The second issue is also solveable. If the same UDP endpoint is used by
different connections in different processes, this makes it difficult to route
incoming traffic to the correct process. However, there are some possible
solutions:

1. The use of OS-specific functionality to route incoming datagrams to the
   same UDP endpoint to different processes based on the DCID in the datagram.

2. Creating a new UDP endpoint for each new peer and telling the peer to use
   this.

(2) can be accomplished via the `preferred_address` option during the QUIC
handshake, however a client is not obliged to support this (and we currently do
not). It would require the dynamic creation of new (socket) BIOs by the QUIC
stack whenever a connection is accepted (or a callback to get a new such BIO
from the application).

(1) can be accomplished if an OS has suitable functionality. For example, Linux
4.5 and later allow an (e)BPF program to be attached to a UDP endpoint to allow
incoming datagrams to be routed to different sockets listening on that endpoint
(via `SO_REUSEPORT`). BPF is powerful enough to parse the DCID out of the first
packet in a QUIC datagram and route using a hashtable mapping DCIDs to sockets.
This functionality is already being used in existing QUIC implementations to
direct incoming traffic to the correct socket.

Of these solutions, (1) is probably preferable. It should be noted that this
solution requires the use of several sockets on the same port, not merely (for
example) different FDs in different processes pointing to the same socket; thus,
some fairly BIO-specific plumbing, as well as OS-specific plumbing, would be
required to make this work.

### Stateless fork support

An alternative model for supporting fork() would be to use a stateless process
for detecting incoming connection attempts akin to `DTLSv1_listen`. This could
be done by an application without much explicit support from us (aside from a
similar support function to parse a DCID out of a packet), but like
`DTLSv1_listen`, requires the application to do a lot of work to handle routing
of incoming connections and so on. Incoming datagram routing would still need to
be provisioned (by the application) using OS-specific functionality such as the
Linux BPF method discussed above. Note that under this model, all SSL objects
are constructed only *after* the fork() call is made, so there are no state
duplication issues. The application would also need to reinject the first packet
sent by a peer after forking.

In this case the listener object created in the child process would have the
first packet sent by a peer injected into it and only ever issue one connection.
We could consider allowing this to be streamlined from an API perspective (e.g.
a server connection not under a listener) if desired, similar to our current
`QUIC_TSERVER` design.

### Prefork support

Prefork is a bit different as the child processes are created before accepting
any connection. Arguably this makes things substantially easier as this means
the state of a particular connection never moves between two processes and is
fully internal to a process. A listener object could be independently created by
every child process after forking, using `SO_REUSEPORT` where supported, so in
principle no duplication of any SSL object needs to occur and all SSL objects
can be created after forking.

Coordination of receive datagram routing remains the issue, again to be
addressed via e.g. BPF. It is possible we could have a fairly turnkey way to
enable this in our API on supported platforms. Since a worker process which
receives a packet for a new connection will need to register the DCID in a
kernel hashtable, there is the possibility that some coordination between worker
processes might be necessary (e.g. shared memory). Determining requirements here
will require further research as regards to how Linux BPF works.

Discussions on the support of DTLS
----------------------------------

Before discussing DTLS API issues and this demo, some facts about DTLS bear
repeating:

  DTLS 1.2 does not incorporate any kind of connection ID in its datagram
  headers. Therefore, different DTLS 1.2 connections can only be demuxed on
  the basis of the 5-tuple.

  The optional Connection ID extension to DTLS 1.2 adds a Connection ID
  field to the DTLS record headers. This enables optional routing other than
  via the 5-tuple.

  DTLS 1.3 completely changes the DTLS record header to be significantly more
  compact and to encrypt more information. The Connection ID extension is
  incorporated as core functionality, though its use is optional. The result
  is a somewhat QUIC-esque record header format.

In short, DTLS connections can be demuxed by 5-tuple or via connection ID (or
by both). Currently, we do not support the DTLS 1.2 Connection ID extension
or DTLS 1.3, so the only demux method we support is via the 5-tuple. However,
consideration should be given to supporting Connection ID based routing in
the future, both to enable DTLS 1.3/Connection ID support and because such
considerations will align well with QUIC support.

OpenSSL's existing DTLS API for server-side operation is somewhat minimal and
relies on some significant subtleties of the Berkeley sockets API as
implemented on certain *nix OSes. The usage pattern is basically:

  // unconnected, with SO_REUSEADDR and (if supported) SO_REUSEPORT
  listening_dgram_bio = socket(SOCK_DGRAM, reuseaddr=1, reuseport=1);
  bind(listening_dgram_bio, ...);

  spare_ssl = SSL_new(dtls_server_ctx);
  SSL_set_bio(spare_ssl, BIO_s_datagram(listening_dgram_sock));

  loop {
    loop on DTLSv1_listen(spare_ssl) until it succeeds; outputs new_peer_addr

    // spare_ssl is now setup with the new association and is effectively
    // "connected" and can be used with SSL_do_handshake/SSL_read/SSL_write
    // etc. A new SSL object must be constructed for future DTLSv1_listen
    // calls.
    new_conn_ssl = spare_ssl;

    // Switch the connected SSL object to doing network I/O with a
    // socket confined to receiving only datagrams from this specific peer
    // L4 endpoint. BIO_CTRL_DGRAM_SET_CONNECTED ensures send() is used
    // instead of sendto(), though this is also enabled automatically
    // if the DTLS stack happens to call BIO_read first before BIO_write
    // (which should not be relied upon).
    conn_dgram_sock = socket(SOCK_DGRAM, reuseaddr=1, reuseport=1);
    bind(conn_dgram_sock); // race condition occurs here
    connect(conn_dgram_sock, new_peer);
    SSL_set_bio(new_conn_ssl,
                BIO_s_datagram(conn_dgram_sock,
                               BIO_CTRL_DGRAM_SET_CONNECTED=new_peer_addr));

    // Handle the connection in some application-specific way.
    do_handle_conn(new_conn_ssl);
  }

In short, incoming datagrams representing new connection requests must be
funnelled to the SSL object on which DTLSv1_listen is repeatedly being
called. However, incoming datagrams related to existing connections must
instead be funnelled to the SSL object associated with that connection.

When using SSL objects with a network socket BIO (BIO_s_datagram),
accomplishing this essentially requires depending on some fairly subtle OS
behaviours:

  - If both bind() and connect() are called on a UDP socket, this sets
    not just the destination address of outgoing datagrams sent with send(),
    but also filters incoming traffic received via recv() so that only
    traffic from the remote L4 endpoint passed to connect() is received.

  - POSIX provides little guidance on how this filtering works and only
    seems to guarantee that foreign traffic will not be returned by recv().
    As such, the default assumption should presumably be that this simply
    applies a simple filter.

  - Linux and some other UNIXes seem to implement this in a more
    sophisticated way than is strictly required by POSIX, where incoming
    traffic from a peer L4 address will be specifically routed to a local
    socket connect()ed to that peer L4 address. This essentially facilitates
    the emulation of a connection-based mode of operation using UDP sockets.

    Using libssl's DTLS functionality on the server side with multiple
    connections and with a BIO_s_datagram depends on the OS working this way.
    There may be POSIX OSes on which this doesn't operate correctly.

  - This OS behaviour is subject to some race conditions. Specifically,
    after a socket has bind() called on it but before connect() is called
    to essentially “filter” the socket to a specified remote L4 address,
    the socket will receive traffic from any remote L4 address and thus
    might eat traffic intended for another connection. This traffic is either
    dropped (hopefully triggering retransmission, at a performance cost)
    or must be manually reinjected by an application (which most applications
    probably don't do properly).

Another option is for an application to use a memory buffer BIO and implement
its own custom routing logic. This provides a large burden on the
application. If this approach is chosen, the preferred option here is
BIO_s_dgram_pair(), which has datagram semantics. However, this is new in
OpenSSL 3.2, therefore any pre-existing applications using DTLS with memory
buffers on the network side would have to use standard BIO_s_bio(), which has
bytestream semantics (or implement a custom BIO method). This might technically
work for DTLS 1.2 as all DTLS 1.2 records have a length header, so the
concatenation of multiple records should be intelligible to the DTLS stack.
However, it will not work for DTLS 1.3, because DTLS 1.3 uses a streamlined
record header in which the length field can be omitted from a record if it is
the last record in a particular datagram.

QUIC's use of connection IDs in a UDP payload to route incoming datagrams to
specific connections creates similar issues to those of DTLS, but because
connection IDs have no relation to UDP endpoints, the bind-connect behaviour
discussed above cannot be used. Currently, on Linux, the use of an eBPF
program to parse QUIC DCIDs in datagrams and route to different sockets
accordingly is becoming popular for QUIC implementations. While we could (and
probably should) implement this in future, its intrinsically OS-specific
nature means such functionality will necessarily be used opportunistically
rather than being a requirement.

The UDP bind-connect behaviour is not ideal for use with QUIC as QUIC allows
peer L4 addresses to change without warning, for example in the case of
connection migration. However, it could be used with the non-connected
“listener” socket handling such incoming datagrams as a special case and
establishing routing for them automatically. The main obstacle here is that
it would require managing multiple BIOs, one for each connected socket. This
implies a significant API shift from our model where we allow and require the
application to provide the network BIO, to a model where libssl has to be
able to instantiate new BIOs on demand. We could give the application some
control over the automatic BIO creation process, but it is nonetheless a
significant API paradigm shift.

To return to DTLS, from a blue sky perspective and without considering
libssl's DTLS stack in its present state, a typical *nix server daemon has a
few options for DTLS implementation. We then list the pros and cons of each
approach with regard to the current state of our DTLS and QUIC APIs:

  - **In-Process Single Multipoint (IPSM).** One unbound UDP socket used with
    sendto()/recvfrom() exclusively, with in-process demux and routing.

    Pro: Single BIO, no new multi-BIO API needed

    Con: Significantly different from the existing DTLS API

    Con: Hard to pin specific connections to specific threads to avoid
         large amounts of contention on central shared state; might
         require inter-thread coordination in some cases

  - **Bind-Connect Group With Fallback Reinjection (BCG-R).** One unbound UDP
    socket plus a group of UDP sockets using the bind-connect() behaviour.
    bind-connect races have the received datagrams reinjected, much as for the
    in-process option above.

    Con: libssl must be able to create new BIOs dynamically, new API,
         significantly new paradigm

    Con: Depends on subtle OS behaviours, fallback reinjection
         means this must be combined with the in-process method above

    Con: Not adequate on its own because it cannot demux multiple QUIC
         connections, or DTLS connections with the Connection ID extension
         enabled, on the same 5-tuple, so must be combined with
         the in-process model

    Pro: Potentially higher kernel send()/recv() performance due to
         internal kernel caching of peer routing decisions

  - **eBPF.** Several unconnected UDP sockets, one per “worker” (e.g.
  connection, thread), which use sendto() to transmit, and which have RX
  traffic vectored to the right socket using a Linux eBPF handler.

    Con: OS-specific, cannot be our only supported model.

    Con: libssl must be able to create new BIOs dynamically, new API,
         significantly new paradigm (`SO_REUSEPORT` eBPF programs require one
         socket per RX receiver)

    Pro: Performant, allows arbitrary RX vectoring as we need it, flexible
         to our needs in future due to eBPF programmability

The BCG(-R) strategy can be subcategorised into Application Managed BCG
(AM-BCG(-R)) and Library Managed BCG (LM-BCG(-R)).

For QUIC all of these are also options. The bind-connect approach with QUIC
means that with connection migration attempts, peer NAT rebinding, etc.
resulting in fallback reinjection via the “listener” socket. This is not
actually too dissimilar to what we would do with eBPF for incoming datagrams not
associated with an existing connection. For DTLS the eBPF option is not that
important unless the connection ID extension is being used as the bind-connect()
option suffices, though it may be a bit cleaner.

The most flexible and most portable albeit least performant option is the
In-Process Single Multipoint (IPSM) option using a single unconnected socket.
Purely on the basis of flexibility and portability, it seems like we are always
going to want to support this as an option for QUIC, and it the model our QUIC
implementation currently uses.

We are thus now faced with four questions:

 - What is the minimal set of changes to adapt a modern application-managed
   Bind-Connect Group (BCG)-based DTLS server application to using a
   libssl-managed IPSM model, for DTLS or for QUIC?

 - What will the preferred usage of DTLS look like in new (“greenfield”)
   applications?

 - Whether or not it is preferred in new code, should AM-BCG be supported
   as a usage model for QUIC (i.e., without switching existing codebases to
   IPSM-based processing)?

 - If it is to be supported, what changes are needed to adapt existing
   AM-BCG-based code to AM-BCG-R?

Deferred questions:

 - API to allow a libssl to autonomously create additional network BIOs
   under libssl control (needed for eBPF, or libssl-managed BCG, post-3.3)

 - What is the minimal set of changes for a modern application-managed
   BCG-based DTLS server application to start using libssl-managed BCG, for
   DTLS or for QUIC?

Comments on proposed changes
----------------------------

Proposed changes to enable QUIC functionality on the server side are described
in each of the demos using `#ifdef USE_QUIC` guards, which clearly demonstrate
what code is needed in the existing non-QUIC code path (which is intended to be
representative of a typical server-side TLS use case) and the proposed changes
to that representative code to enable it for QUIC.

In some cases, a more general refactor is necessary to enable an application for
QUIC, but that refactor can also be used for handling e.g. TLS over TCP
connections. For example, servers which accept TLS over TCP connections using
direct handling of socket FDs and accept(2) obviously require substantive
changes to enable use of a userspace QUIC implementation. For the OpenSSL QUIC
case, this means refactoring this code to use the proposed SSL listener API.
Since this listener API is capable of supporting both QUIC and TLS over TCP,
such a refactor does not need to be conditional on whether the demo is built to
use QUIC. This code is guarded with `#ifdef USE_LISTENER`. In principle, an
application can permanently change its code to use the SSL listener API and
support both TLS over TCP and QUIC if it is willing to require OpenSSL 3.3 or
later.

In other words, the changes needed for existing applications are the code blocks
guarded by `#ifdef USE_LISTENER` as well as those guarded by `#ifdef USE_QUIC`.
It is worth noting that the QUIC-specific code is extremely minimal, amounting
to little more than changing `TLS_server_method()` to
`OSSL_QUIC_server_method()` and `SOCK_STREAM` to `SOCK_DGRAM`. The vast majority
of the implications for server-side applications in terms of code changes
required derive from the need to switch to a libssl-provided listener interface.
