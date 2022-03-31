ddd-03-fd-blocking
==================

This proposed diff demonstrates the theoretical minimal changes for the example:

    - TLS_client_method is changed to QUIC_client_method
    - SOCK_STREAM, IPPROTO_TCP is changed to SOCK_DGRAM, IPPROTO_UDP

This just about works, just. It just about works and serious thought should be
given to whether we actually want to support this, but it is possible:

    - The destination UDP endpoint is set via connect(). Connection migration
      can be handled by subsequent calls to connect() which changes the
      destination address, or by using sendto() etc. The latter is probably a
      better idea anyway so connect() can be seen as just a highly backwards
      compatible way to pass the destination endpoint to libssl. Once the FD
      is passed to libssl, libssl can obtain the destination endpoint if
      it needs to know by calling getpeername(3).

    - As for ddd-01, it is assumed that the application spends a lot of time
      in calls to libssl (as it is a blocking application) or at least calls it
      regularly. Since synchronous users of libssl are probably fairly simple
      this may be true quite often. If it is not the case, either a
      BIO_pump/SSL_pump call must be made regularly via some means, or
      thread-assisted operation should be used.

      NOTE: Since programming errors on the part of the application are more
      likely here it is possible we should plan to provide some debugging
      functionality in libssl that reports when libssl has not been called
      often enough. Functionality intended for use in debug builds of
      applications only that reports excessively late timer events.
      Something to consider.

