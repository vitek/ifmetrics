#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if.h>
#include <stdlib.h>
#include <assert.h>

#include "nlrequest.h"
#include "getifn.h"

#define MAX_ROUTES 64

struct nlmsghdr* routes[MAX_ROUTES];
int n_routes = 0;

int enumerate_callback(struct nlmsghdr *n, void *u) {
    struct rtmsg *r;
    struct rtattr *a = NULL;
    int l, *ifn = u;

    if (n->nlmsg_type != RTM_NEWROUTE) {
        fprintf(stderr, "NETLINK: Got response for wrong request.\n");
        return -1;
    }

    r = NLMSG_DATA(n);
    l = NLMSG_PAYLOAD(n, sizeof(struct rtmsg));
    a = RTM_RTA(r);

    if (r->rtm_table != RT_TABLE_MAIN)
        return 0;
    
    while(RTA_OK(a, l)) {
        switch(a->rta_type) {
            case RTA_OIF:

                if (RTA_PAYLOAD(a) != sizeof(int)) {
                    fprintf(stderr, "NETLINK: Received corrupt RTA_OIF payload.\n");
                    return -1;
                }
                
                if (*((int*) RTA_DATA(a)) == *ifn) {

                    if (n_routes < MAX_ROUTES) {
                        struct nlmsghdr* copy;

                        if (!(copy = malloc(n->nlmsg_len))) {
                            fprintf(stderr, "Could not allocate memory.\n");
                            return -1;
                        }
                            
                        memcpy(copy, n, n->nlmsg_len);
                        routes[n_routes++] = copy;

                    } else
                        fprintf(stderr, "Found too many routes.\n");
                            
                    break;
                }

                
        }
        
        a = RTA_NEXT(a, l);
    }

    return 0;
}

int enumerate(int s, int ifn, int family) {
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char a[1024];
    } req;
    
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_MATCH;
    req.n.nlmsg_type = RTM_GETROUTE;
    
    req.r.rtm_family = family;
    req.r.rtm_table = RT_TABLE_MAIN;
    
    return netlink_request(s, (struct nlmsghdr*) &req, enumerate_callback, &ifn);
}

struct nlmsghdr* set_route_metric(struct nlmsghdr* n, int metric) {
    struct rtmsg *r;
    struct rtattr *a = NULL;
    int l, t;

    r = NLMSG_DATA(n);
    l = NLMSG_PAYLOAD(n, sizeof(struct rtmsg));
    a = RTM_RTA(r);
    
    while(RTA_OK(a, l)) {
        switch(a->rta_type) {
            case RTA_PRIORITY:

                if (RTA_PAYLOAD(a) != sizeof(int)) {
                    fprintf(stderr, "NETLINK: Received corrupt RTA_PRIORITY payload.\n");
                    return NULL;
                }

                *((int*) RTA_DATA(a)) = metric;
                return n;
        }
        
        a = RTA_NEXT(a, l);
    }

    if ((n = realloc(n, (t = n->nlmsg_len+1024))))
        addattr32(n, t, RTA_PRIORITY, metric);
    else
        fprintf(stderr, "realloc() failed.\n");

    return n;
}

int delete_route(int s, struct nlmsghdr* n) {
    assert(s >= 0 && n);
    
    n->nlmsg_type = RTM_DELROUTE;
    n->nlmsg_flags = NLM_F_REQUEST;

    return netlink_request(s, n, NULL, NULL);
}

int add_route(int s, struct nlmsghdr* n) {
    assert(s >= 0 && n);
    
    n->nlmsg_type = RTM_NEWROUTE;
    n->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;

    return netlink_request(s, n, NULL, NULL);
}


int go(char *iface, int family, int metric) {
    int r = -1, j;
    int s = -1, ifn;

    if ((s = netlink_open()) < 0)
        return -1;
    
    if ((ifn = getifn(s, iface)) < 0)
        goto finish;

    n_routes = 0;
    if (enumerate(s, ifn, family) < 0)
        goto finish;

    if (n_routes) {
        for (j = 0; j < n_routes; j++) {
             if (delete_route(s, routes[j]) >= 0)
                 if ((routes[j] = set_route_metric(routes[j], metric)))
                     add_route(s, routes[j]);
            
            free(routes[j]);
        }
    }
    
    r = 0;
    
finish:
    
    if (s >= 0)
        close(s);
    
    return r;
}


static void usage(const char *prog)
{
    const char *b;

    if ((b = strrchr(prog, '/')))
        b++;
    else
        b = prog;

    printf("Usage: %s [-6] <iface> [metric]\n"
           "\n"
           "%s is a tool for setting the metrics of all IPv4 or IPv6 routes\n"
           "attached to a given network interface at once.\n"
           "\n"
           "   -6         Set IPv6 metric, IPv4 is default\n"
           "   <iface>    The interface\n"
           "   <metric>   The new metric (default: 0)\n", b, b);
}

int main(int argc, char *argv[]) {
    char *iface;
    int metric;
    int optind;
    int family = AF_INET;

    for (optind = 1; optind < argc; optind++) {
        char *arg = argv[optind];

        if (!strcmp(arg, "-6")) {
            family = AF_INET6;
        } else if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            break;
        }

    }

    if ((argc - optind) < 2) {
        usage(argv[0]);
        return 0;
    }

    iface = argv[optind];
    metric = argc > 2 ? atoi(argv[optind + 1]) : 0;

    return go(iface, family, metric) < 0 ? 1 : 0;
}
