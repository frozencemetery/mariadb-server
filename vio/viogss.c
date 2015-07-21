/*
  Copyright (c) 2015 Red Hat, Inc.

  Permission to use, copy, modify, and/or distribute this software for
  any purpose with or without fee is hereby granted, provided that the
  above copyright notice and this permission notice appear in all
  copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
  WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
  AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
  DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
  OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
  PERFORMANCE OF THIS SOFTWARE.
*/

#ifdef HAVE_GSSAPI

#include "vio_priv.h"

int vio_gss_error(Vio *me)
{
  printf("TODO(rharwood) love me!\n");
}

/* Always buffered */
size_t vio_gss_read(Vio *me, uchar *buf, size_t n)
{
  /*
    vio->read_buf: start of buffer
    vio->read_pos: start of encrypted data
    vio->read_end: current insertion point
   */
  ssize_t len, missing, packet_size;
  OM_uint32 major, minor;
  gss_buffer_desc input, output;
  
  if (vio_gss_has_data(me))
  {
    /* a packet is decrypted and ready to go */
    size_t get = MY_MIN(n, me->read_pos - me->read_buf);
    memcpy(buf, me->read_buf, get);
    memmove(me->read_buf, me->read_buf + get,
            me->read_end - me->read_buf - get);
    me->read_pos -= get;
    me->read_end -= get;
    DBUG_RETURN(get);
  }

  missing = me->read_pos + 4 - me->read_end;
  if (missing > 0)
  {
    /* we need to get the length */
    len = vio_read(me, me->read_end, missing);
    DBUG_ASSERT(len <= missing);
    if (len < 0)
    {
      printf("TODO(rharwood) pick up the pieces and try not to cry\n");
    }
    me->read_end += len;
    missing = me->read_pos + 4 - me->read_end;
    if (missing > 0)
      DBUG_RETURN(0); 
  }

  /* we now have the length */
  memcpy(&packet_size, me->read_pos, 4);
  packet_size = ntohl(packet_size);
  if (packet_size > VIO_READ_BUFFER_SIZE - 4)
  {
    printf("TODO(rharwood) why you gots to be malicious :(\n");
  }

  missing = me->read_pos + packet_size + 4 - me->read_end;
  if (missing > 0)
  {
    /* try to get the rest of the packet */
    len = vio_read(me, me->read_end, missing);
    DBUG_ASSERT(len <= missing);
    if (len < 0)
    {
      printf("TODO(rharwood) actually cry this time\n");
    }
    me->read_end += len;
    missing = me->read_pos + packet_size + 4 - me->read_end;
    if (missing > 0)
      DBUG_RETURN(0);
  }

  /* we now have a full packet ready to decrypt */
  input.value = me->read_buf + 4;
  input.length = packet_size;
  major = gss_unwrap(&minor, me->gss_ctxt, &input, &output, &conf, NULL);
  if (GSS_ERROR(major))
  {
    printf("TODO(rharwood) crypto is hard\n");
  }
  else if (conf == 0)
  {
    printf("TODO(rharwood) like, *really* hard\n");
  }

  DBUG_ASSERT(output.length < packet_size + 4);
  memcpy(me->read_buf, output.value, output.length);
  me->read_pos = me->read_end = me->read_buf + output.length;
  gss_release_buffer(&minor, &output);

  /* recur at most once; "free" since it's a tail call */
  DBUG_RETURN(vio_gss_read(me, buf, n));
}

size_t vio_gss_write(Vio *me, const uchar *buf, size_t len)
{
  OM_uint32 major, minor;
  gss_buffer_desc input, output;
  int conf;
  uchar *send_buf;
  uint32 packetlen;

  /* pre-compute what this looks like encrypted */  
  input.value = buf;
  input.length = len;

  major = gss_wrap(&minor, me->gss_ctxt, 1, GSS_C_QOP_DEFAULT, &input,
		   &conf, &output);
  if (GSS_ERROR(major))
  {
    printf("TODO(rharwood) handle\n");
  }
  else if (!conf)
  {
    printf("TODO(rharwood) bail?\n");
  }

  /*
    It "should be" faster to hit malloc here than to do two sends.  We
    also need to do the malloc anyway if we're non-blocking.

    Additionally, we need four bytes for length because GSS-encrypted
    packets can be larger, and it's valid to ask for a maxlen packet
    to be encrypted.

    Though the underlying buffer in output.value is allocated using malloc(),
    we cannot count on this behavior as it is not required by 2744.
  */
  send_buf = malloc(output.length + 4);
  if (!send_buf)
  {
    printf("TODO(rharwood) derp derp derp\n");
  }
  packetlen = htonl(output.length);
  memcpy(send_buf, &packetlen, 4);
  memcpy(send_buf + 4, output.value, output.length);

  major = gss_release_buffer(&minor, &output);

  DBUG_RETURN(vio_write(me, send_buf, output.length + 4));
}

int vio_gss_close(Vio *me)
{
  if (!vio)
    return;
  else if (vio->gss_ctxt != GSS_C_NO_CONTEXT)
    (void) gss_delete_sec_context(&minor, &vio->gss_ctxt, GSS_C_NO_BUFFER);

  DBUG_RETURN(vio_close(me));
}

my_bool vio_gss_has_data(Vio *me)
{
  return me->read_buf != me->read_pos;
}

#endif /* HAVE_GSSAPI */
