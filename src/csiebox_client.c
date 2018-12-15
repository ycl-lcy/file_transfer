#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"
#include "hash.c"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h> 
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h> //header for inotify

#define MAXBUFFERSIZE 1000000
#define FILE_BUFFER_SIZE 1000000
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

char **inode_list;

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);

//read config file, and connect to server
void csiebox_client_init(
  csiebox_client** client, int argc, char** argv) {
  csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
  if (!tmp) {
    fprintf(stderr, "client malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_client));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = client_start(tmp->arg.name, tmp->arg.server);
  if (fd < 0) {
    fprintf(stderr, "connect fail\n");
    free(tmp);
    return;
  }
  tmp->conn_fd = fd;
  *client = tmp;
}

void inotify_client(int fd){
  int length, i = 0;
  int wd;
  char buffer[EVENT_BUF_LEN];
  memset(buffer, 0, EVENT_BUF_LEN);

  //create a instance and returns a file descriptor
  while ((length = read(fd, buffer, EVENT_BUF_LEN)) > 0) {
    i = 0;
    while (i < length) {
      struct inotify_event* event = (struct inotify_event*)&buffer[i];
      printf("event: (%d, %d, %s)\ntype: ", event->wd, strlen(event->name), event->name);
      if (event->mask & IN_CREATE) {
        printf("create ");
      }
      if (event->mask & IN_DELETE) {
        printf("delete ");
      }
      if (event->mask & IN_ATTRIB) {
        printf("attrib ");
      }
      if (event->mask & IN_MODIFY) {
        printf("modify ");
      }
      if (event->mask & IN_ISDIR) {
        printf("dir\n");
      } else {
        printf("file\n");
      }
      i += EVENT_SIZE + event->len;
    }
    memset(buffer, 0, EVENT_BUF_LEN);
  }

  //inotify_rm_watch(fd, wd);
  close(fd);


}

void sync_file(csiebox_client* client, char *file_path, int file_type){
  char *full_path = (char*)malloc(strlen(client->arg.path) + strlen(file_path));
  memset(full_path, 0, (strlen(client->arg.path) + strlen(file_path)));
  strcpy(full_path, client->arg.path);
  strcat(full_path, "/");
  strcat(full_path, file_path);
  fprintf(stderr, "%s\n", full_path);
  //FILE *file = fopen(path, "rw");
  
  csiebox_protocol_meta meta;
  meta.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  meta.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  //other entry
  meta.message.header.req.datalen = sizeof(meta) - sizeof(meta.message.header);
  meta.message.body.pathlen = strlen(file_path);
  lstat(full_path, &meta.message.body.stat);
  //for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
    //fprintf(stderr, "%d\n", meta.message.body.hash[i]);
  //}
  send_message(client->conn_fd, &meta, sizeof(meta));
  fprintf(stderr, "%s\n", file_path);
  send_message(client->conn_fd, file_path, strlen(file_path));
  send_message(client->conn_fd, &file_type, sizeof(file_type));
  if(file_type == 0){
      md5_file(full_path, meta.message.body.hash);
      csiebox_protocol_header header;
      memset(&header, 0, sizeof(header));
      if(recv_message(client->conn_fd, &header, sizeof(header))){
        if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
           header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META){
          if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE){
            FILE *pfile = fopen(full_path, "r");
            fseek(pfile, 0, SEEK_END);
            int file_size = ftell(pfile);
            fseek(pfile, 0, SEEK_SET);
            csiebox_protocol_file file;
            memset(&file, 0, sizeof(file));
            file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
            file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
            file.message.header.req.datalen = sizeof(file) - sizeof(file.message.header);
            file.message.body.datalen = file_size;
            send_message(client->conn_fd, &file, sizeof(file));
            char buf[FILE_BUFFER_SIZE];
            for(int i = file_size; i > 0; i -= FILE_BUFFER_SIZE){
                if(i < FILE_BUFFER_SIZE){
                    fread(buf, sizeof(char), i, pfile);
                    send_message(client->conn_fd, buf, i);
                }
                else{
                    fread(buf, sizeof(char), FILE_BUFFER_SIZE, pfile);
                    send_message(client->conn_fd, buf, FILE_BUFFER_SIZE);
                }
            }
            fclose(pfile);
            fprintf(stderr, "file_size%d\n", file_size);
          }
        }
      }
  }
  //if(file_type == 1){
  
  //}
  if(file_type == 2){
    char buf[PATH_MAX];
    int n = readlink(full_path, buf, PATH_MAX);
    buf[n] = '\0';
    fprintf(stderr, "wwww%d\n", strlen(buf));
    send_message(client->conn_fd, buf, PATH_MAX);
  }
  //FILE *p = fopen("jizz", "rw");
  //char buf[MAXBUFFERSIZE];
  //fread(buf, sizeof(char), MAXBUFFERSIZE, p);
  //fprintf(stderr, "FILE SIZE: %d\n", strlen(buf));
  //send_message(client->conn_fd, buf, strlen(buf));
}

void tree_walk(csiebox_client* client, char *dir_name){
    struct dirent *file;
    DIR *dir = opendir(dir_name);
    while((file = readdir(dir)) != NULL){
        if(strcmp(file->d_name, "..") != 0 && strcmp(file->d_name, ".") != 0){
            char full_path[PATH_MAX];
            strcpy(full_path, dir_name);
            strcat(full_path, "/");
            strcat(full_path, file->d_name);
            fprintf(stderr, "%s\n", &full_path[strlen(client->arg.path)+1]);
            if(file->d_type == DT_REG){
                fprintf(stderr,  "reg%s\n", &full_path[strlen(client->arg.path)+1]);
                sync_file(client, &full_path[strlen(client->arg.path)+1], 0);
            }
            if(file->d_type == DT_DIR){ 
                sync_file(client, &full_path[strlen(client->arg.path)+1], 1);
                tree_walk(client, full_path);
            }
            if(file->d_type == DT_LNK){
                sync_file(client, &full_path[strlen(client->arg.path)+1], 2);
            }
        }
    }
}
//this is where client sends request, you sould write your code here
int csiebox_client_run(csiebox_client* client) {
  if (!login(client)) {
    fprintf(stderr, "login fail\n");
    return 0;
  }
  fprintf(stderr, "login success\n");
  
  //====================
  //        TODO: add your client-side code here
  //===================
  //char *msg = "blablabla";
  //send_message(client->conn_fd, msg, strlen(msg));
  
  //siebox_protocol_header req;
  //memset(&req, 0, sizeof(req));
  //req.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  //req.req.op = GAY2;
  //while(1){send_message(client->conn_fd, &req, sizeof(req));}
  //req.req.op = GAY;
  //send_message(client->conn_fd, &req, sizeof(req));
  
  //sync_file(client, "gg", 0);
  int inotify_fd = inotify_init();
  
  if (inotify_fd < 0) {
    perror("inotify_init ggggggggggggggggggggggggggggggg");
  }

  struct hash client_hash;
  //add directory "." to watch list with specified events
  int wd = inotify_add_watch(inotify_fd, client->arg.path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
  
  tree_walk(client, client->arg.path);
  inotify_client(inotify_fd);

  //sync_file(client, "jizz");
  while(1);
  return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {
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
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
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

static int login(csiebox_client* client) {
  csiebox_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
  md5(client->arg.passwd,
      strlen(client->arg.passwd),
      req.message.body.passwd_hash);
  if (!send_message(client->conn_fd, &req, sizeof(req))) {
    fprintf(stderr, "send fail\n");
    return 0;
  }
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(client->conn_fd, &header, sizeof(header))) {
    if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
        header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
        header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
      client->client_id = header.res.client_id;
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}
