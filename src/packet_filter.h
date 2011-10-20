

#ifndef __PACKET_FILTER_H
#define __PACKET_FILTER_H

#include <stdbool.h>
#include <stdlib.h>

#include "config.h"

/*
 * Prototypes.
 */
bool packet_filter(struct config_s *config, const uint8_t *packet,
    size_t packet_len);

#endif          /* __PACKET_FILTER_H */
