/************************************************************************
 *   IRC - Internet Relay Chat, common/fdpass.c
 *   Copyright (C) 2009 sd <sd@hysteria.cz>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "os.h"
#include "s_defines.h"

/* TPROXY is sole user of fdpassing for now, and others here as needed */
#if defined(USE_TPROXY)

#define FDPASS_C
#include "s_externs.h"
#undef FDPASS_C

#if 0
#define logerr(fmt...) { Debug((DEBUG_ERROR,fmt)); return -1; }
#define logerrx(fmt...) { Debug((DEBUG_ERROR,fmt)); return -1; }
#else
#define logerr(fmt...) { return -1; }
#define logerrx(fmt...) { return -1; }
#endif

int
send_fd(int sock, int fd)
{
#if defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	char ch = '\0';
	ssize_t n;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(sock, &msg, 0)) == -1)
		logerr("%s: sendmsg(%d)", __func__, fd);
	if (n != 1)
		logerrx("%s: sendmsg: expected sent 1 got %ld", __func__,
		    (long)n);

	return (0);
#else
# error No supported FD passing primitives found
#endif
}

int
receive_fd(int sock)
{
#if defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	ssize_t n;
	char ch;
	int fd;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = tmp;
	msg.msg_controllen = sizeof(tmp);
#endif

	if ((n = recvmsg(sock, &msg, 0)) == -1)
		logerr("%s: recvmsg", __func__);
	if (n != 1)
		logerrx("%s: recvmsg: expected received 1 got %ld", __func__,
		    (long)n);

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	if (msg.msg_accrightslen != sizeof(fd))
		logerrx("%s: no fd", __func__);
#else
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL)
		logerrx("%s: no message header", __func__);
#ifndef BROKEN_CMSG_TYPE
	if (cmsg->cmsg_type != SCM_RIGHTS)
		logerrx("%s: expected type %d got %d", __func__,
		    SCM_RIGHTS, cmsg->cmsg_type);
#endif
	fd = (*(int *)CMSG_DATA(cmsg));
#endif
	return (fd);
#else
# error No supported FD passing primitives found
#endif
}

#endif /* TPROXY */
