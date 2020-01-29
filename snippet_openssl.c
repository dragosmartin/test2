unsigned char *buf, *wbuf;
    size_t fragoff, fraglen, msglen, reclen, align = 0;
    unsigned int rectype, versmajor, msgseq, msgtype, clientvers, cookielen;
    BIO *rbio, *wbio;
    BIO_ADDR *tmpclient = NULL;
    PACKET pkt, msgpkt, msgpayload, session, cookiepkt;

    if (s->handshake_func == NULL) {
        /* Not properly initialized yet */
        SSL_set_accept_state(s);
    }

    /* Ensure there is no state left over from a previous invocation */
    if (!SSL_clear(s))
        return -1;
//this is a comment line
//this is a comment line
//this is a comment line
//this is a comment line
//this is a comment line
//this is a comment line
//this is a comment line
    ERR_clear_error();

    rbio = SSL_get_rbio(s);
    wbio = SSL_get_wbio(s);

    if (!rbio || !wbio) {
        SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_BIO_NOT_SET);
        return -1;
    }

    /*
     * Note: This check deliberately excludes DTLS1_BAD_VER because that version
     * requires the MAC to be calculated *including* the first ClientHello
     * (without the cookie). Since DTLSv1_listen is stateless that cannot be
     * supported. DTLS1_BAD_VER must use cookies in a stateful manner (e.g. via
     * SSL_accept)
     */
    if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
        SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_UNSUPPORTED_SSL_VERSION);
        return -1;
    }

    if (!ssl3_setup_buffers(s)) {
        /* SSLerr already called */
        return -1;
    }
    buf = RECORD_LAYER_get_rbuf(&s->rlayer)->buf;
    wbuf = RECORD_LAYER_get_wbuf(&s->rlayer)[0].buf;
#if defined(SSL3_ALIGN_PAYLOAD)
# if SSL3_ALIGN_PAYLOAD != 0
    /*
     * Using SSL3_RT_HEADER_LENGTH here instead of DTLS1_RT_HEADER_LENGTH for
     * consistency with ssl3_read_n. In practice it should make no difference
     * for sensible values of SSL3_ALIGN_PAYLOAD because the difference between
     * SSL3_RT_HEADER_LENGTH and DTLS1_RT_HEADER_LENGTH is exactly 8
     */
    align = (size_t)buf + SSL3_RT_HEADER_LENGTH;
    align = SSL3_ALIGN_PAYLOAD - 1 - ((align - 1) % SSL3_ALIGN_PAYLOAD);
# endif
#endif
    buf += align;

    do {
        /* Get a packet */

        clear_sys_error();
        n = BIO_read(rbio, buf, SSL3_RT_MAX_PLAIN_LENGTH
                                + DTLS1_RT_HEADER_LENGTH);
        if (n <= 0) {
            if (BIO_should_retry(rbio)) {
                /* Non-blocking IO */
                goto end;
            }
            return -1;
        }

        if (!PACKET_buf_init(&pkt, buf, n)) {
            SSLerr(SSL_F_DTLSV1_LISTEN, ERR_R_INTERNAL_ERROR);
            return -1;
        }
