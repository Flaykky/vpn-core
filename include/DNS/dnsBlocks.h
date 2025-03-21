#ifndef DNSBLOCKS_H
#define DNSBLOCKS_H

#include <stdbool.h>

/*
dns для блокировки айпи логгеров: 149.112.112.112; 9.9.9.9
dns для блокировки рекламы: 94.140.14.14; 94.140.15.15
*/

#define DNS_FOR_LOGGER "149.112.112.112" 
#define DNS_ADBLOCK "94.140.14.14"
#define DNS_QUAD9 "9.9.9.9" 
#define ANOTHER_DFL "94.140.15.15" // запасной dns для адблока


#endif 
