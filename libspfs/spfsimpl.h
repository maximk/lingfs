/*
 * Copyright (C) 2006 by Latchesar Ionkov <lucho@ionkov.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* fcall.c */
Spfcall *sp_version(Spreq *req, Spfcall *tc);
Spfcall *sp_auth(Spreq *req, Spfcall *tc);
Spfcall *sp_attach(Spreq *req, Spfcall *tc);
Spfcall *sp_flush(Spreq *req, Spfcall *tc);
Spfcall *sp_walk(Spreq *req, Spfcall *tc);
Spfcall *sp_open(Spreq *req, Spfcall *tc);
Spfcall *sp_create(Spreq *req, Spfcall *tc);
Spfcall *sp_read(Spreq *req, Spfcall *tc);
Spfcall *sp_write(Spreq *req, Spfcall *tc);
Spfcall *sp_clunk(Spreq *req, Spfcall *tc);
Spfcall *sp_remove(Spreq *req, Spfcall *tc);
Spfcall *sp_stat(Spreq *req, Spfcall *tc);
Spfcall *sp_wstat(Spreq *req, Spfcall *tc);

/* srv.c */
void sp_srv_add_req(Spsrv *srv, Spreq *req);
void sp_srv_remove_req(Spsrv *srv, Spreq *req);
void sp_srv_add_workreq(Spsrv *srv, Spreq *req);
void sp_srv_remove_workreq(Spsrv *srv, Spreq *req);

/* fmt.c */
int sp_printstat(FILE *f, Spstat *st, int dotu);
int sp_dump(FILE *f, u8 *data, int datalen);

/* conn.c */
Spfcall *sp_conn_new_incall(Spconn *conn);
void sp_conn_free_incall(Spconn *, Spfcall *);
