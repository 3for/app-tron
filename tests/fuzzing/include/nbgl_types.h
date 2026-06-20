#pragma once

// Minimal host-side mock of the NBGL <nbgl_types.h>. The standalone fuzz build
// does not link NBGL; only network.h needs `nbgl_icon_details_t` (embedded in
// network_info_t) and the GCS sources never touch its fields.

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t nbgl_bpp_t;
typedef uint8_t nbgl_color_map_t;

typedef struct nbgl_icon_details_s {
    uint16_t width;
    uint16_t height;
    nbgl_bpp_t bpp;
    bool isFile;
    const uint8_t *bitmap;
} nbgl_icon_details_t;
