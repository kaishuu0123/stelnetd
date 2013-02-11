#include <stdio.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>

#define __USE_GNU 1
#define __USE_XOPEN 1
#include <stdlib.h>
#undef __USE_GNU
#undef __USE_XOPEN

#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#include <arpa/telnet.h>
#include <arpa/inet.h>

#define BUFSIZE 4000
#define MIN(a, b) ((a) > (b) ? (b) : (a))

static char *loginpath = NULL;
static char *argv_init[] = {NULL, NULL};
static int maxfd;

struct tsession {
  struct tsession *next;
  int sockfd, ptyfd;
  int shell_pid;
  char *buf1, *buf2;
  int rdidx1, wridx1, size1;
  int rdidx2, wridx2, size2;
};

static struct tsession *sessions;

void
usage(void)
{
  printf("Usage: stelnetd [-p port] [-l loginprogram] [-d]\n");
  printf("\n");
  printf("    -p port\n");
  printf("    -l loginprogram\n");
  printf("    -d daemonize\n");
  printf("\n");
  exit(1);
}

void
perror_msg_and_die(char *text)
{
  fprintf(stderr, "%s", text);
  exit(1);
}

void
error_msg_and_die(char *text)
{
  perror_msg_and_die(text);
}

static char *
remove_iacs(unsigned char *bf, int len, int *processed, int *num_totty)
{
  unsigned char *ptr = bf;
  unsigned char *totty = bf;
  unsigned char *end = bf + len;

  while (ptr < end) {
    if (*ptr != IAC) {
      *totty++ = *ptr++;
    } else {
      if ((ptr + 2) < end) {
        ptr += 3;
      } else {
        break;
      }
    }
  }

  *processed = ptr - bf;
  *num_totty = totty - bf;

  return memmove(ptr - *num_totty, bf, *num_totty);
}

static int
getpty(char *line)
{
  int p;

  p = getpt();
  if (p < 0) {
    close(p);
    return -1;
  }

  if (grantpt(p) < 0 || unlockpt(p) < 0) {
    close(p);
    return -1;
  }

  strcpy(line, (const char *)ptsname(p));

  return p;
}

static void
send_iac(struct tsession *ts, unsigned char command, int option)
{
  char *b = ts->buf2 + ts->rdidx2;

  *b++ = IAC;
  *b++ = command;
  *b++ = option;
  ts->rdidx2 += 3;
  ts->size2 += 3;
}

static struct tsession *
make_new_session(int sockfd)
{
  struct termios termbuf;
  int pty, pid;
  static char tty_name[32];
  struct tsession *ts = (struct tsession *)malloc(sizeof(struct tsession));
  int t1, t2;

  ts->buf1 = (char *)malloc(BUFSIZE);
  ts->buf2 = (char *)malloc(BUFSIZE);
  ts->sockfd = sockfd;

  ts->rdidx1 = ts->wridx1 = ts->size1 = 0;
  ts->rdidx2 = ts->wridx2 = ts->size2 = 0;

  pty = getpty(tty_name);
  if (pty < 0) {
    fprintf(stderr, "All network ports in use!\n");
    return 0;
  }

  if (pty > maxfd)
    maxfd = pty;

  ts->ptyfd = pty;

  send_iac(ts, DO, TELOPT_ECHO);
  send_iac(ts, DO, TELOPT_LFLOW);
  send_iac(ts, WILL, TELOPT_ECHO);
  send_iac(ts, WILL, TELOPT_SGA);

  if ((pid = fork()) < 0) {
    perror("fork");
  }

  if (pid == 0) {
    int i, t;

    for (i = 0; i <= maxfd; i++) {
      close(i);
    }

    if (setsid() < 0) {
      perror_msg_and_die("setsid");
    }

    t = open(tty_name, O_RDWR | O_NOCTTY);
    if (t < 0) {
      perror_msg_and_die("Could not open tty");
    }

    t1 = dup(0);
    t2 = dup(1);

    tcsetpgrp(0, getpid());
    if (ioctl(t, TIOCSCTTY, NULL)) {
      perror_msg_and_die("Could not set controlling tty");
    }

    tcgetattr(t, &termbuf);
    termbuf.c_lflag |= ECHO;
    termbuf.c_oflag |= ONLCR|XTABS;
    termbuf.c_iflag |= ICRNL;
    termbuf.c_iflag &= ~IXOFF;
    tcsetattr(t, TCSANOW, &termbuf);

    execv(loginpath, argv_init);
    /* NOT REACHED */
    perror_msg_and_die("execv");
  }

  ts->shell_pid = pid;
  return ts;
}

static void
free_session(struct tsession *ts)
{
  struct tsession *t = sessions;

  if (t == ts)
    sessions = ts->next;
  else {
    while (t->next != ts) {
      t = t->next;
    }
    t->next = ts->next;
  }

  free(ts->buf1);
  free(ts->buf2);

  kill(ts->shell_pid, SIGKILL);
  wait4(ts->shell_pid, NULL, 0, NULL);
  close(ts->ptyfd);
  close(ts->sockfd);

  if (ts->ptyfd == maxfd || ts->sockfd == maxfd)
    maxfd--;
  if (ts->ptyfd == maxfd || ts->sockfd == maxfd)
    maxfd--;

  free(ts);
}

int
main(int argc, char *argv[])
{
  struct sockaddr_in sa;
  int masterfd;
  fd_set rdfdset, wrfdset;
  int selret;
  int on = 1;
  int portnbr = 23;
  int c, ii;
  int daemonize = 0;
  char *interface_name = NULL;
  char *appname;

  while ((c = getopt(argc, argv, "i:p:l:hd")) != -1) {
    switch (c) {
    case 'p':
      portnbr = atoi(optarg);
      break;
    case 'i':
      interface_name = strdup(optarg);
      break;
    case 'l':
      loginpath = strdup(optarg);
      break;
    case 'd':
      daemonize = 1;
      break;
    case 'h':
    default:
      usage();
      exit(1);
    }
  }

  /* get appname */
  appname = strrchr(argv[0], '/');
  if (!appname)
    appname = argv[0];
  else
    appname++;

  if (!loginpath) {
    loginpath = "/bin/sh";
  }

  if (access(loginpath, X_OK) < 0) {
    fprintf(stderr, "\"%s\"", loginpath);
    perror_msg_and_die(" is no valid executable!\n");
  }

  printf("%s: starting\n", appname);
  printf("  port: %i; interface: %s; login program: %s\n",
      portnbr, (interface_name) ? interface_name : "any", loginpath);

  argv_init[0] = loginpath;
  sessions = 0;

  masterfd = socket(AF_INET, SOCK_STREAM, 0);
  if (masterfd < 0) {
    perror("socket");
    return 1;
  }
  (void)setsockopt(masterfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  memset((void *)&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(portnbr);

  if (interface_name) {
    /* NOT IMPL */
  } else {
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  /* setup openlog */
  openlog(appname, LOG_NDELAY | LOG_PID, LOG_DAEMON);
  syslog(LOG_INFO, "%s (port: %i, ifname: %s, login: %s) startup succeeded\n",
      appname, portnbr, (interface_name) ? interface_name : "any", loginpath);
  closelog();

  if (bind(masterfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    return 1;
  }

  if (listen(masterfd, 1) < 0) {
    perror("listen");
    return 1;
  }

  if (daemonize) {
    if (daemon(0, 1) < 0)
      perror_msg_and_die("daemon");
  }

  maxfd = masterfd;
  while (1) {
    struct tsession *ts;

    FD_ZERO(&rdfdset);
    FD_ZERO(&wrfdset);

    FD_SET(masterfd, &rdfdset);

    ts = sessions;
    while (ts) {
      if (ts->size1 > 0) {
        FD_SET(ts->ptyfd, &wrfdset);
      }

      if (ts->size1 < BUFSIZE) {
        FD_SET(ts->sockfd, &rdfdset);
      }

      if (ts->size2 > 0) {
        FD_SET(ts->sockfd, &wrfdset);
      }

      if (ts->size2 < BUFSIZE) {
        FD_SET(ts->ptyfd, &rdfdset);
      }

      ts = ts->next;
    }

    selret = select(maxfd + 1, &rdfdset, &wrfdset, 0, 0);
    if (!selret)
      break;

    if (FD_ISSET(masterfd, &rdfdset)) {
      int fd, salen;

      salen = sizeof(sa);
      if ((fd = accept(masterfd, (struct sockaddr *)&sa, &salen)) < 0) {
        continue;
      }

      struct tsession *new_ts;
      openlog(appname, LOG_NDELAY, LOG_DAEMON);
      syslog(LOG_INFO, "connection from: %s\n", inet_ntoa(sa.sin_addr));
      closelog();

      new_ts = make_new_session(fd);
      if (new_ts) {
        new_ts->next = sessions;
        sessions = new_ts;
        if (fd > maxfd)
          maxfd = fd;
      } else {
        close(fd);
      }
    }

    ts = sessions;
    while (ts) {
      int maxlen, w, r;
      struct tsession *next = ts->next;

      if (ts->size1 && FD_ISSET(ts->ptyfd, &wrfdset)) {
        int processed, num_totty;
        char *ptr;

        maxlen = MIN(BUFSIZE - ts->wridx1, ts->size1);
        ptr = remove_iacs(ts->buf1 + ts->wridx1, maxlen, &processed, &num_totty);

        ts->wridx1 += processed - num_totty;
        ts->size1 -= processed - num_totty;

        w = write(ts->ptyfd, ptr, num_totty);
        if (w < 0) {
          perror("write");
          free_session(ts);
          ts = next;
          continue;
        }

        ts->wridx1 += w;
        ts->size1 -= w;

        if (ts->wridx1 == BUFSIZE)
          ts->wridx1 = 0;
      }

      if (ts->size2 && FD_ISSET(ts->sockfd, &wrfdset)) {
        maxlen = MIN(BUFSIZE - ts->wridx2, ts->size2);
        w = write(ts->sockfd, ts->buf2 + ts->wridx2, maxlen);
        if (w < 0) {
          perror("write");
          free_session(ts);
          ts = next;
          continue;
        }

        ts->wridx2 += w;
        ts->size2 -= w;
        if (ts->wridx2 == BUFSIZE)
          ts->wridx2 = 0;
      }

      if (ts->size1 < BUFSIZE && FD_ISSET(ts->sockfd, &rdfdset)) {
        maxlen = MIN(BUFSIZE - ts->rdidx1, BUFSIZE - ts->size1);
        r = read(ts->sockfd, ts->buf1 + ts->rdidx1, maxlen);
        if (!r || (r < 0 && errno != EINTR)) {
          free_session(ts);
          ts = next;
          continue;
        }

        if (!*(ts->buf1 + ts->rdidx1 + r - 1)) {
          r--;
          if (!r)
            continue;
        }

        ts->rdidx1 += r;
        ts->size1 += r;
        if (ts->rdidx1 == BUFSIZE)
          ts->rdidx1 = 0;
      }

      if (ts->size2 < BUFSIZE && FD_ISSET(ts->ptyfd, &rdfdset)) {
        maxlen = MIN(BUFSIZE - ts->rdidx2, BUFSIZE - ts->size2);
        r = read(ts->ptyfd, ts->buf2 + ts->rdidx2, maxlen);
        if (!r || (r < 0 && errno != EINTR)) {
          free_session(ts);
          ts = next;
          continue;
        }

        for (ii = 0; ii < r; ii++) {
          if (*(ts->buf2 + ts->rdidx2 + ii) == 3) {
            fprintf(stderr, "found <CTRL>-<C> in data!\n");
          }
        }
        ts->rdidx2 += r;
        ts->size2 += r;
        if (ts->rdidx2 == BUFSIZE)
          ts->rdidx2 = 0;
      }

      if (ts->size1 == 0) {
        ts->rdidx1 = 0;
        ts->wridx1 = 0;
      }

      if (ts->size2 == 0) {
        ts->rdidx2 = 0;
        ts->wridx2 = 0;
      }

      ts = next;
    }
  }

  return 0;
}
