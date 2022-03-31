ddd-02-conn-nonblocking
=======================

In addition to the changes in ddd-01-conn-blocking, the following issues arise:

  - The application must be able to poll. This means that it must have some
    OS-level synchronization object which is suitable for polling (e.g. a file
    descriptor). The application may well want to poll other things than libssl
    at the same time, so this needs to be something which can be polled
    simultaneously with other things, not some special "poll" call provided
    by libssl. The only thing meeting this criterion for varied POSIX systems is
    a file descriptor.

  - A valid design question is do we want to guarantee that the application
    only needs to poll a single FD to determine readiness of a given
    connection? It is possible we might have some reason to keep multiple
    FDs internally (multiple UDP sockets etc.) but this means we need to have
    a mechanism to tell the application some arbitrary number of FDs need to be
    polled.

    My rough view is that:

    - we don't need more than one UDP socket TX-wise, because we can direct
      destination addresses with sendto/sendmsg/sendmmsg.

    - do we need more than one UDP socket RX-wise? If we bind to 0.0.0.0
      there is no issue, and if an application wants to bind to a specific
      interface it presumably does so for a reason. But what if an application
      wants to bind to a specific interface (say for example, 192.0.2.1) and
      later wants to do connection migration?

      This seems like a relatively rare thing. Usually only servers would want
      to bind to a specific interface and are less likely to do migration.

      Some OSes provide means to aggregate FDs for purposes of polling. For
      example, on Linux, I believe you can add FDs to an epoll FD and then call
      poll(2) on that(?). Apparently only POLLIN is reported for this however so
      this probably would not match expectations. Moreover we probably shouldn't
      plan on this being available on all OSes.

      PROPOSED SOLUTION: To minimise necessary changes, our best hope is
      probably to plan to require the application to poll only a single FD. If
      we ever end up needing multiple sockets, we can provide an advanced
      interface which applications can choose to implement if they wish. In the
      worst case they can forego some functionality if they don't implement it.
      But to be clear, there is no immediate identified need for multiple
      sockets at this time.

  - The application needs to know when to listen for each of
    POLLIN/POLLOUT/POLLERR on the file descriptor it has been told about.

    CHANGE: The function `BIO_get_fd` is changed to `BIO_get_poll_fd` as the
        semantics differ; a QUIC implementation will not wish to guarantee any
        particular properties about the FD returned for polling. In practice we
        can have `BIO_get_fd` work against QUIC BIOs if we wish, but be
        considered deprecated.

  - TX can depend on RX and vice versa (SSL_ERROR_WANT_READ/WRITE).

    Q. What if the QUIC stack wants to listen for POLLIN even during
       a poll caused by WANT_WRITE (more likely) / wants to listen for POLLOUT even
       during a poll caused by WANT_READ (less likely but possible, e.g. frames
       transmitted on a timer)?

    PROPOSED SOLUTION: POLLIN should always be listened for.

    CHANGE: Applications should always listen for POLLIN.

    Q. What if the QUIC stack starts to need to read during WANT_WRITE polling?
    A. Possibly the application should simply always poll for POLLIN.
       We probably want the QUIC state machine to always handle incoming frames
       immediately even if TX queues are full so this would make sense.

    PROPOSED SOLUTION: POLLIN should always be listened for.

    CHANGE: If applications do not already test POLLIN during WANT_WRITE they
        will need to be changed to do so. Arguably they should already do this to
        handle TLS close notifications etc.

    Q. What if the QUIC stack starts to need to write during WANT_READ polling?
    A. The QUIC stack should be able to predict at what point in the future
       it will want to do a spontaneous write so this can be handled by whatever
       solution is conceived for 'timer issues' below.

    PROPOSED SOLUTION: This is handled by whatever solution we choose for our timer
        issue. After timer events are handled SSL_read/SSL_write should be
        tried again which results in a new SSL_ERROR_WANT_READ/WRITE return
        code. If libssl wants to be notified for both POLLIN and POLLOUT
        it can return SSL_ERROR_WANT_WRITE due to the decision that POLLIN
        should always be handled above.

        Applications will need to ensure they retry SSL_read/SSL_write
        after a timer event (i.e. timer events effectively imply POLLIN|POLLOUT
        from an application perspective.)

        (Should we also offer the abillity to get a SSL_ERROR_WANT_READ/WRITE
         as a result of the BIO_pump call?)

  - Timer issues:

    - The QUIC stack may need to randomly send frames (e.g. keepalives)
      even when the application is not calling SSL_read/SSL_write for a long
      time (e.g. an hour).

    - So arrangements must be made for some call to libssl to be made
      periodically.

      PROPOSED SOLUTION: A call, BIO_pump (/SSL_pump) is introduced which can be used
      when an application wishes to allow libssl to process events without
      calling read/write functions.

      CHANGE: See below.

    - It is possible this can be handled automatically on platforms where
      threads can be used but this cannot be assumed on all platforms.

    - Worst case, provide a "get wakeup time" function along with the "get FD"
      function which indicates the deadline by which libssl should next be
      called.

      PROPOSED SOLUTION: A function BIO_get_timeout is introduced which returns
      when libssl next wants to be called.

      CHANGE: See below.

    - Or we could provide an fd which becomes readable at the right time using
      timerfd. But this is Linux-specific and thus probably a non-starter.

  - Ways in which we can make things easier for existing applications
    on platforms which can use threads ("thread-assisted operation"):

    - No need to pump manually or handle timeouts.

    Q. In thread-assisted operation, how do we cause the application to exit
       poll() if a timer event we handled on a libssl-internal thread means
       SSL_read/SSL_write is now possible? (e.g. no keepalives for an interval,
       connection is broken, SSL_write will now return a non-temporary error)

    A. Synthetic write to our own socket (which we ignore when we read it), or
       shutdown/close the fd? Crude but should work fine.

  CHANGES due to timer issues:

    - In thread-assisted operation, no changes are needed. No timeout
      handling or pump calls need be made by the application.

    - In non-thread-assisted operation:

      - The BIO_get_timeout function must be called whenever not calling
        libssl to determine when to next call BIO_pump.

To demonstrate the changes needed both in the thread-assisted and
non-thread-assisted case, ddd-02-conn-nonblocking is split into two
identical files with different changes on top of them.

Other concerns:

- Use of buffering BIOs (BIO_f_buffer) on the network side is apparently common
  in many applications. It appears that this is workable but a new BIO method,
  say BIO_f_dgram_buffer, will need to be created which preserves datagram
  semantics.

  It is possible we could remove the need for this change with "cleverness",
  like having BIO_f_buffer support dgram and non-dgram modes and auto-switch
  when it detects it is being pushed into a BIO chain which is using QUIC, etc.
  but I'm not sure it's worth it.

