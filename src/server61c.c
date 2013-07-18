#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_PORT 10099
#define SERVER_BACKLOG 64
#define FRAG_LENGTH 64

typedef struct server {
  int sock;
  struct sockaddr_in addr;
} server_t;

typedef struct conn {
  int sock;
  struct sockaddr_in addr;
} conn_t;

int init_server(server_t *s) {
  int retval = 0;
  memset(s, 0, sizeof(server_t));
  s->sock = socket(AF_INET, SOCK_STREAM, 0);
  s->addr.sin_family = AF_INET;
  s->addr.sin_port = htons(SERVER_PORT);
  s->addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(s->sock, (struct sockaddr *) &s->addr, sizeof(struct sockaddr_in))) retval |= 1;
  if (listen(s->sock, SERVER_BACKLOG)) retval |= 2;
  return retval;
}

char *get_request(conn_t *c) {
  char *req;
  void *req_buffer = NULL, *frag_buffer = malloc(FRAG_LENGTH);
  size_t req_length = 0, frag_length = 0;
  while (frag_length = recv(c->sock, frag_buffer, FRAG_LENGTH, 0)) {
    req_buffer = realloc(req_buffer, req_length + frag_length + 1);
    if (req_buffer == NULL) return NULL;
    memcpy(req_buffer + req_length, frag_buffer, frag_length);
    req_length += frag_length;
    req = (char *) req_buffer;
    if (req[req_length-2] == 0xd && req[req_length-1] == 0xa) break;
  }
  req[req_length] = '\0';
  return req;
}

int get_resource_fd(conn_t *c, char *req) {
  char filename[64];
  int i = 0;
  while (*req++ != '/') ;
  while (req[i] > 0x20) filename[i++] = req[i];
  filename[i] = '\0';
}

void send_reply(conn_t *c, char *req) {
  int fd = get_resource_fd(c, req);
}

void handle_conn(server_t *s) {
  conn_t c;
  char *request;
  int addr_size = sizeof(c.addr);
  c.sock = accept(s->sock, (struct sockaddr *) &c.addr, &addr_size);
  request = get_request(&c);
  if (request) {
    printf("%s\n", request);
    send_reply(&c, request);
  }
  close(c.sock);
}

int main(int argc, char **argv) {
  server_t s;
  int err_code;
  if (err_code = init_server(&s)) printf("Error code: %d\n", err_code);
  handle_conn(&s);
  return 0;
}
