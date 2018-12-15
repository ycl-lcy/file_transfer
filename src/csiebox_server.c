#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static void handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory
#define FILE_BUFFER_SIZE 1000000
//read config file, and start to listen
void csiebox_server_init(
  csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)
      malloc(sizeof(csiebox_client_info*) * getdtablesize());
  if (!tmp->client) {
    fprintf(stderr, "client list malloc fail\n");
    close(fd);
    free(tmp);
    return;
  }
  memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
  tmp->listen_fd = fd;
  *server = tmp;
}

//wait client to connect and handle requests from connected socket fd
//===============================
//		TODO: you need to modify code in here and handle_request() to support I/O multiplexing
//===============================
int csiebox_server_run(csiebox_server* server) {
  int conn_fd, conn_len;
  struct sockaddr_in addr;
  fd_set master;
  fd_set read_fds;
  int fd_max = server->listen_fd;
  FD_ZERO(&master);
  FD_ZERO(&read_fds);
  FD_SET(server->listen_fd, &master);
  while(1) {
    memset(&addr, 0, sizeof(addr));
    conn_len = 0;
    //memcpy(&read_fds, &master, sizeof(fd_set));
    read_fds = master;
    select(fd_max+1, &read_fds, NULL, NULL, NULL);
    for(int i = 0; i <= fd_max; i++){
        if(FD_ISSET(i, &read_fds)){
            if(i == server->listen_fd){
                // waiting client connect
                conn_fd = accept(
                  server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
                fprintf(stderr, "conn_fd%d\n", conn_fd);
                if (conn_fd < 0) {
                  if (errno == ENFILE) {
                      fprintf(stderr, "out of file descriptor table\n");
                      continue;
                    } else if (errno == EAGAIN || errno == EINTR) {
                      continue;
                    } else {
                      fprintf(stderr, "accept err\n");
                      fprintf(stderr, "code: %s\n", strerror(errno));
                      break;
                    }
                }
                FD_SET(conn_fd, &master);
                if(conn_fd > fd_max){
                    fd_max = conn_fd;
                }
            }
            else{
                // handle request from connected socket fd
                handle_request(server, i);
                fprintf(stderr, "handle_request_complete conn_fd is %d\n", i);
            }
        }

    }
  }
  return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  close(tmp->listen_fd);
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc != 2) {
    return 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
      }
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}

//this is where the server handle requests, you should write your code here
static void handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  int flag = 1;
  //while (flag && recv_message(conn_fd, &header, sizeof(header))) {
  if(recv_message(conn_fd, &header, sizeof(header))) {
    if (header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ) {
    switch (header.req.op) {
      case CSIEBOX_PROTOCOL_OP_LOGIN:
        fprintf(stderr, "login%d\n", conn_fd);
        csiebox_protocol_login req;
        if (complete_message_with_header(conn_fd, &header, &req)) {
          login(server, conn_fd, &req);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_META:
        fprintf(stderr, "sync meta\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
          //====================
          //        TODO: here is where you handle sync_meta and even sync_file request from client
          //====================
            char *file_path = (char*)malloc(PATH_MAX);
            memset(file_path, 0, PATH_MAX);
            recv_message(conn_fd, file_path, meta.message.body.pathlen);
            fprintf(stderr, "jizz%d\n", meta.message.body.pathlen);
            //fprintf(stderr, "%s\n", file_path);
            char *homedir = get_user_homedir(server, server->client[conn_fd]);
            //fprintf(stderr, "%s\n", homedir);
            char *full_path = (char*)malloc(strlen(homedir) + strlen(file_path));
            memset(full_path, 0, (strlen(homedir) + strlen(file_path)));
            //memset!!!!!
            strcpy(full_path, homedir);
            strcat(full_path, "/");
            strcat(full_path, file_path);
            //fprintf(stderr, "%s\n", file_path);
            fprintf(stderr, "%s\n", full_path);
            int file_type;
            if(recv_message(conn_fd, &file_type, sizeof(file_type))){
                if(file_type == 0){
                    uint8_t hash[MD5_DIGEST_LENGTH];
                    md5_file(full_path, hash);
                    int flag = 0;
                    for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
                        if(meta.message.body.hash[i] != hash[i]){
                            flag = 1;
                            break;
                        }
                    }
                    csiebox_protocol_header header_res;
                    memset(&header_res, 0, sizeof(header_res));
                    header_res.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
                    header_res.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
                    header_res.res.datalen = 0;
                    if(flag){
                        header_res.res.status = CSIEBOX_PROTOCOL_STATUS_MORE; 
                        send_message(conn_fd, &header_res, sizeof(header_res));
                        FILE *pfile = fopen(full_path, "w+");
                        csiebox_protocol_file file;
                        memset(&file, 0, sizeof(file));
                        recv_message(conn_fd, &file, sizeof(file));
                        int file_size = file.message.body.datalen;
                        char buf[FILE_BUFFER_SIZE];
                        //fprintf(stderr, "QQ%s\n", full_path);
                        for(int i = file_size; i > 0; i -= FILE_BUFFER_SIZE){
                            if(i < FILE_BUFFER_SIZE){
                                fprintf(stderr, "QQ\n");
                                recv_message(conn_fd, buf, i);
                                fprintf(stderr, "QAQ%s\n", buf);
                                fwrite(buf, sizeof(char), i, pfile);
                            }
                            else{
                                recv_message(conn_fd, buf, FILE_BUFFER_SIZE);
                                fwrite(buf, sizeof(char), FILE_BUFFER_SIZE, pfile);
                            }
                        }
                        fclose(pfile);
                        fprintf(stderr, "file_size%d\n", file_size);
                    }
                    else{
                        header_res.res.status = CSIEBOX_PROTOCOL_STATUS_OK; 
                        send_message(conn_fd, &header_res, sizeof(header_res));
                    }
                }
                if(file_type == 1){
                    DIR *dir = opendir(full_path);
                    if(!dir){
                        if(ENOENT == errno){
                            mkdir(full_path, 0755);
                        }
                    }
                }
                if(file_type == 2){
                    char buf[PATH_MAX];
                    recv_message(conn_fd, buf, PATH_MAX);
                    //fprintf(stderr, "www%d\n", strlen(buf));
                    symlink(buf, full_path);///!!!!!!!!!!!!!!!!!!!!!!
                }
            }
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
        fprintf(stderr, "sync hardlink\n");
        csiebox_protocol_hardlink hardlink;
        if (complete_message_with_header(conn_fd, &header, &hardlink)) {
          //====================
          //        TODO: here is where you handle sync_hardlink request from client
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "sync end\n");
        csiebox_protocol_header end;
          //====================
          //        TODO: here is where you handle end of synchronization request from client
          //====================
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
        fprintf(stderr, "rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
          //====================
          //        TODO: here is where you handle rm file or directory request from client
          //====================
        }
        break;
      case GAY:
        flag = 0;
        break;
      default:
        fprintf(stderr, "unknown op %x\n", header.req.op);
        break;
    }
    }
  }
  else{
    fprintf(stderr, "end of connection\n");
    logout(server, conn_fd);
  }
}

//open account file to get account information
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}

//handle the login request from client
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account\n");
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

