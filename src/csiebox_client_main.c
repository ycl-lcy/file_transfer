#include "csiebox_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h> //header for inotify
#include <string.h>
#include <unistd.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))



//where the server starts
int main(int argc, char** argv) {
  csiebox_client* box = 0;
  csiebox_client_init(&box, argc, argv);
  if (box) {
    csiebox_client_run(box);
  }
  csiebox_client_destroy(&box);
  return 0;
}
