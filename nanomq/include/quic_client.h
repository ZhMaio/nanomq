#ifndef QUIC_CLIENT_H
#define QUIC_CLIENT_H

#include <nng/mqtt/mqtt_client.h>
#include <nng/supplemental/util/platform.h>
#include <nng/nng.h>
#include "conf.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int  quic_run();

extern int quic_start(int argc, char **argv);
extern int quic_dflt(int argc, char **argv);

#endif
