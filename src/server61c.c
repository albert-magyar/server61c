#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <curses.h>

#define SERVER_BACKLOG 64
#define FRAG_LENGTH 64
#define CHUNK_SIZE 256

char * const resp_ok_format_string =
  "HTTP/1.1 %d %s\r\nDate: %s\r\nServer: server61c\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n%s";

char * const not_found_page = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body></html>";

char * const found_page = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>200 OK</title>\n</head><body>\n<h1>Page Found</h1>\n<p>The requested URL was found on this server.</p>\n</body></html>";

typedef struct resp {
  int code;
  char *explanation, *date, *content;
} resp_t;

typedef struct server {
  int sock;
  struct sockaddr_in addr;
} server_t;

typedef struct conn {
  int sock;
  struct sockaddr_in addr;
} conn_t;

void error(char *msg) {
  printf("ERROR: %s\n", msg);
  exit(-1);
}

int init_server(server_t *s, uint16_t port) {
  int retval = 0;
  memset(s, 0, sizeof(server_t));
  s->sock = socket(AF_INET, SOCK_STREAM, 0);
  s->addr.sin_family = AF_INET;
  s->addr.sin_port = htons(port);
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
    if (req_buffer == NULL) {
      free(req);
      return NULL;
    }
    memcpy(req_buffer + req_length, frag_buffer, frag_length);
    req_length += frag_length;
    req = (char *) req_buffer;
    if (req[req_length-2] == 0xd && req[req_length-1] == 0xa) break;
  }
  free(frag_buffer);
  req[req_length] = '\0';
  return req;
}

int get_resource_fd(conn_t *c, char *req) {
  char filename[64];
  int i = 0;
  while (*req++ != '/') ;
  while (req[i] > 0x20) filename[i++] = req[i];
  filename[i] = '\0';
  return open(filename, 0);
}

char *serialize(resp_t *info) {
  int resp_max_length = 1024 + strlen(info->content);
  char *resp_string = malloc(resp_max_length);
  snprintf(resp_string,
	  (size_t) resp_max_length,
	  resp_ok_format_string,
	  info->code,
	  info->explanation,
	  info->date,
	  strlen(info->content),
	  info->content);
  return resp_string;
}

ssize_t craft_http_response(int fd, char **resp) {
  resp_t info;
  time_t date = time(NULL);
  info.date = ctime(&date);
  info.date[strlen(info.date)-1] = '\0';
  if (fd >= 0) {
    int current_length = 0;
    ssize_t bytes_read = 0;
    info.code = 200;
    info.explanation = "OK";
    info.content = NULL;
    do {
      info.content = realloc(info.content,current_length+CHUNK_SIZE);
      if (!info.content) exit(-1);
      bytes_read = pread(fd, (void *) info.content+current_length, CHUNK_SIZE, current_length);
      current_length += bytes_read;
    } while (bytes_read > 0);
    info.content[current_length] = '\0';
  } else {
    info.code = 404;
    info.explanation = "Not Found";
    info.content = malloc(strlen(not_found_page)+1);
    strcpy(info.content,not_found_page);
  }
  *resp = serialize(&info);
  free(info.content);
  return strlen(*resp);
}

void serve_request(conn_t *c, char *req) {
  int fd = get_resource_fd(c, req);
  char *resp = NULL;
  size_t resp_length = craft_http_response(fd, &resp);
  ssize_t bytes_sent = send(c->sock, (void *) resp, resp_length, 0);
  close(fd);
  free(resp);
}

void handle_conn(server_t *s) {
  conn_t c;
  char *request;
  int addr_size = sizeof(c.addr);
  c.sock = accept(s->sock, (struct sockaddr *) &c.addr, &addr_size);
  request = get_request(&c);
  if (request) {
    serve_request(&c, request);
    free(request);
  }
  close(c.sock);
}

int main(int argc, char **argv) {
  server_t s;
  char input = '\0';
  int err_code;
  fd_set read_fs;
  int max_sock;
  uint16_t port;
  struct timeval timeout;
  if (argc != 2) error("usage is \"server61c <port>\"");
  int tmp = atoi(argv[1]);
  if (tmp > 65535) error("specified port unavailable");
  port = (uint16_t) tmp;
  err_code = init_server(&s, port);
  if (err_code & 0x1) error("could not bind socket");
  if (err_code & 0x2) error("could not listen()");
  printf("server61c starting...\npress q <Enter> to quit\n");
  while (input != 'q') {
    FD_ZERO(&read_fs);
    FD_SET(STDIN_FILENO, &read_fs);
    FD_SET(s.sock, &read_fs);
    max_sock = (s.sock > STDIN_FILENO) ? s.sock+1 : STDIN_FILENO+1;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    select(max_sock, &read_fs, NULL, NULL, &timeout);
    if (FD_ISSET(STDIN_FILENO, &read_fs)) {
      read(0, (void *) &input, 1);
    } else if (FD_ISSET(s.sock, &read_fs)) {
      handle_conn(&s);
    }
  }
  return 0;
}
