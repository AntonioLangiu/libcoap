#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#define WITH_CONTIKI 1

#define uthash_fatal(msg) return

#define DEBUG 0
#define HAVE_STRNLEN 1
#define HAVE_SNPRINTF 1

/* there is no file-oriented output */
#define COAP_DEBUG_FD NULL
#define COAP_ERR_FD   NULL

#include "contiki-conf.h"

#if defined(PLATFORM) && PLATFORM == PLATFORM_MC1322X
/* Redbee econotags get a special treatment here: endianness is set
 * explicitly, and assert() is defined as emtpy directive unless
 * HAVE_ASSERT_H is given.
 */ 

#define BYTE_ORDER UIP_LITTLE_ENDIAN

#ifndef HAVE_ASSERT_H
# define assert(x)
#endif

#endif /* defined(PLATFORM) && PLATFORM == PLATFORM_MC1322X */

#ifndef BYTE_ORDER
# ifdef UIP_CONF_BYTE_ORDER
#  define BYTE_ORDER UIP_CONF_BYTE_ORDER
# else
#  error "UIP_CONF_BYTE_ORDER not defined"
# endif /* UIP_CONF_BYTE_ORDER */
#endif /* BYTE_ORDER */

#endif /* _CONFIG_H_ */

