ddd-05-mem-nonblocking
======================

Of the five demos, this one poses the greatest challenge in terms of allowing it
to be adapted for QUIC with minimal changes.

The discussions of the diffs for the previous nonblocking demos are also
relevant here (e.g. always listening for POLLIN, etc.).

Broadly, the premise of this demo is that the network side of a SSL object is
fed with a memory BIO pair, so that the application is in complete control not
just of feeding data into the application side of libssl (SSL_read/SSL_write)
but also into the network side. This allows the application to use libssl as a
pure state machine which does no I/O itself.

The problems with adapting this to QUIC include:

- QUIC uses UDP rather than TCP and the contents of its UDP packets are
  not concatenatable, whereas TCP uses a byte stream model. So existing
  applications based around this approach will assume they can pull data out
  of the memory BIOs in arbitrary-length chunks and feed them to the
  network, which is not the case. Moreover, if libssl just writes the UDP
  datagram payload to the memory BIO for each UDP datagram it wants ton
  send, the BIO will end up containing the concatenation of these datagrams
  with no way for the application to determine where one datagram should
  start and end.

  - One possible solution is to put a length header on each UDP datagram.
    However this requires the application to parse this length header and
    parse datagrams out of the BIO bytestream. Since datagrams will probably
    not happen to be aligned at the start of the application's call to
    BIO_read, this will require the application to copy partial datagrams to
    a staging area in order to "unfragment" them before finally sending
    them. This is neither performant nor a reasonable ask upon the
    application.

  - Looking at the big picture, the *reason* an application wants to use
    a memory BIO on the network side is so it can use libssl as a pure
    state machine and be in control of all I/O.

    Since supporting the exact same interface (memory BIOs with bytestream
    semantics) is infeasible for the reasons given above, the next best thing we
    can do is to ensure that we accommodate this use case for applications, so
    that there is some rougly analagous solution available to them. This may not
    be "minimal changes" in the sense of "the changes are small in an absolute
    sense" but it does meet the definition of "minimal changes" where "minimal"
    means "as small as actually possible". While adaptation of this kind of
    application (demo 5) will require more work than the other kinds of
    application (as demonstrated in demos 1 through 4) we can at least provide
    an interface which applications will find familiar and which lacks any
    excessive impedence discontinuities with their own code.

  - There already exists BIO_dgram, which is used with DTLS. This causes
    BIO_read/BIO_write to work similarly to recv/send. This works on
    a file descriptor; there is no analagous BIO_dgram_mem.
    Such a BIO could be created, which would model datagram semantics
    for read/write operations (i.e., a sequence of BIO_write calls
    with given lengths results in an exactly matching sequence of
    BIO_read calls with the same lengths returned).

  - There are some caveats for this idea. In order for this to work:

    - applications must ensure there is a guaranteed 1:1 correspondance
      between send/recv and BIO_read/BIO_write calls; and

    - the buffer passed to BIO_read() and recv() must always be big
      enough to receive the largest possible packet, else silent
      truncation occurs.

    The latter is an unfortunate design issue with the Berkeley sockets API
    for SOCK_DGRAM, which is replicated here in BIO_read which simply serves
    as a wrapper for it. The caller thus has to know the worst-case UDP
    datagram payload size, but knowing this requires knowledge of the
    network or at least the configuration of local network interfaces.

    (Random factoid: this design issue once in the past led me to determine
    the maximum size of an incoming UDP datagram as

      max(64 KiB, max(MTU of every local interface))

    -- reason being that an IPv6 fragmentation header has a 16-bit length field,
    so an IP packet greater than 64 KiB (using the IPv6 jumbogram header) can
    only be sent if you have an interface with a native MTU exceeding it.
    Another option is to use MSG_PEEK | MSG_TRUNC on systems which support it
    but this requires calling recv twice per packet.)

  - For the buffer size issue, our options for supporting existing applications
    include:

    - Using a maximum MTU of 1472 by default; then any application using
      old BIO_read/BIO_write calls will work so long as it uses a buffer
      of at least 1472 bytes (and there is a 1:1 correspondance of BIO calls and
      syscalls).

    - Applications which can support larger MTUs (e.g. a network with
      jumbo frames) could indicate support via some method TBD, such as
      capability flags (see below).

    In this model, for the purposes of compatibility and minimising changes:

    - BIO_ctrl_get_write_guarantee (BIO_C_GET_WRITE_GUARANTEE) would always
      return either 0 or a value >=1472. (This is a change from BIO_dgram,
      which does not implement BIO_C_GET_WRITE_GUARANTEE.)

    - BIO_ctrl_pending (BIO_CTRL_PENDING) returns the size of the next frame
      which will be popped by BIO_read. It's not possible to determine how many
      frames are queued in a frame-BIO or the total amount of data queued by
      using this function. (This is a change from BIO_dgram, which always
      returns 0 for BIO_CTRL_PENDING.)

    The following APIs could be provided for applications which want to
    support larger MTUs (new applications, and applications willing to make
    larger changes):

    ```c
      /*
       * A flag settable on BIO_dgram_mem. A BIO_read call will not truncate,
       * but instead fail if the frame is too large for the provided buffer. The
       * application must call BIO_ctrl_pending() to determine the necessary
       * buffer size and try again.
       */
      int BIO_dgram_set_no_trunc(bio, 1);

      /*
       * Returns libssl's idea of what our maximum UDP payload size is.
       */
      ssize_t BIO_get_max_dgram_len(BIO *bio);
    ```

  - If we do support things like variable destination addresses
    (connection migration):

    - PR #5257 is relevant prior art because it adapts BIO_dgram to support
      variable source and destination addresses. It introduces four functions
      taking `BIO_ADDR *`:

      ```
        BIO_get_dgram_dest   (BIO_CTRL_DGRAM_GET_ADDR)
        BIO_get_dgram_origin (BIO_CTRL_DGRAM_GET_PEER)
        BIO_set_dgram_dest   (BIO_CTRL_DGRAM_SET_ADDR)
        BIO_set_dgram_origin (BIO_CTRL_DGRAM_SET_PEER)
      ```

      The get functions can be called after a BIO_read and yield information
      on the last datagram received. Likewise, the set functions can be called
      before a BIO_write and control the source and destination of the write.

      This API should be fine.

    - We do need a way for the application to indicate
      its capabilities in this regard. We cannot have libssl queueing packets to
      a BIO_dgram_mem and setting destination addresses which get ignored
      because the application is just using send(2).

      One option would be to have something like

      ```c
        /*
         * The side which reads from one direction of a BIO_dgram_mem
         * guarantees to handle a destination address set on the
         * datagram it reads.
         */
        #define BIO_DGRAM_CAP_DST_ADDR      (1U<<0)

        /*
         * The side which writes to one direction of a BIO_dgram_mem
         * guarantees to set a source address on every frame it writes.
         */
        #define BIO_DGRAM_CAP_SRC_ADDR      (1U<<1)

        int BIO_set_dgram_caps(BIO *bio, uint32_t caps);
    ```

    If the application does not support these capabilities functionality
    like connection migration would be disabled.

    Another option is to simply probe support by seeing if (supposing
    the PR #5257 API above is used) BIO_CTRL_DGRAM_SET_PEER, etc.
    are implemented. Actually, this goes together with the above
    mechanism:

      - QUIC internals can probe the BIO to see if
        BIO_CTRL_DGRAM_SET_PEER works (if it fails the first time it tries it,
        connection migration etc. is permanently disabled for the connection).

      - BIO_dgram can implement this BIO_ctrl normally.

      - However, BIO_dgram_mem doesn't know what the application does, so
        BIO_set_dgram_caps would be an explicit (and BIO_dgram_mem-specific) call to let BIO_dgram_mem
        know whether it should support BIO_CTRL_DGRAM_SET_PEER, etc. If the caps
        were not set, attempts to call BIO_CTRL_DGRAM_SET_PEER would fail and
        the QUIC internals would automatically assume connection migration and
        so on can't be used.

  - The above API is a little excessive in its copying because data must be
    copied into the memory BIO and then out again before it gets passed to a
    syscall. Eventually we could offer an alternative API for
    BIO_dgram_mem, which also alleviates some though not all of the issues
    around having to know the maximum buffer length in advance:

        /*
         * If a dgram is available to be popped from the queue, outputs a
         * pointer to the dgram data and its length.
         *
         * The caller must call BIO_return_dgram once done with the buffer.
         *
         * If BIO_get_dgram is called multiple times before calling
         * BIO_return_dgram, multiple packets are popped (i.e., the popping
         * happens during BIO_get_dgram, not during BIO_return_dgram, and
         * multiple dgrams can be popped and transmitted simultaneously).
         *
         * If BIO_get_dgram_dest, etc. are called, they should be called
         * after calling this and constitute metadata attached to the
         * buffer returned by the last call to BIO_get_dgram.
         */
        int BIO_get_dgram(BIO *bio, void **dgramp, size_t *dgram_len);

        /*
         * Return a dgram buffer to the BIO once it is done being transmitted.
         * The buffer is freed or internally reused and its contents become
         * indeterminate. The dgram has been popped from the queue; a subsequent
         * call to BIO_get_dgram gets the next dgram, if any.
         */
        int BIO_return_dgram(BIO *bio, void *dgramp, size_t dgram_len);

        /*
         * Queues a datagram into the BIO_dgram_mem. The buffer is
         * freed when no longer needed (i.e. during BIO_return_dgram on
         * the other side) by calling free_func. free_arg is an opaque value
         * passed to the callback.
         *
         * If BIO_set_dgram_dest, etc., are called, they should be called before
         * calling this and constitute metadata attached to the next buffer
         * passed to BIO_put_dgram.
         */
        int BIO_put_dgram(BIO *bio, const void *buf, size_t buf_len,
                          void (*free_func)(void *buf, size_t *buf_len, void *arg),
                          void *free_arg);

        /*
         * If an application calls BIO_set_dgram_dest, etc. (or similar) but
         * does not call BIO_put_dgram, it should call this to unset what it set
         * and ensure the metadata it set does not get associated with a
         * subsequent frame.
         */
        void BIO_dgram_abort_put(BIO *bio);

    Usage of this API is demonstrated in demo 5 variant
    ddd-05-mem-nonblocking-alt.c.

