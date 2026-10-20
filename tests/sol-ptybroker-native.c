/* SPDX-License-Identifier: MIT */
/* Include production server code to exercise exact queue boundaries and the
 * credential rejection branch without requiring a second host account. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>
static int foreign_uid;
static int fixture_getsockopt(int fd, int level, int opt, void *value, socklen_t *len)
{
    int rc = getsockopt(fd, level, opt, value, len);
    if (!rc && foreign_uid && level == SOL_SOCKET && opt == SO_PEERCRED)
        ((struct ucred *)value)->uid = geteuid() + 1;
    return rc;
}
#define getsockopt fixture_getsockopt
#include "../loadables/_ptybroker/server.c"
#undef getsockopt

static void pair(struct pb_peer *peer, int *remote)
{
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) == 0);
    memset(peer, 0, sizeof *peer);
    peer->fd = fds[0];
    *remote = fds[1];
}

static void input_queue(void)
{
    struct pb_server s = {.master=-1};
    s.input = malloc(PB_INPUT_LIMIT);
    assert(s.input);
    /* A wrapped tail with three bytes free: rejection must leave the input
     * untouched, then the exact final three bytes must fit across the wrap. */
    memset(s.input, 0xa7, PB_INPUT_LIMIT);
    s.input_head = 2;
    s.input_size = PB_INPUT_LIMIT - 3;
    struct pb_peer peer;
    int remote;
    pair(&peer, &remote);
    struct pb_packet p = {.magic=PB_MAGIC,.type=PB_INPUT,.size=4};
    memcpy(p.data,"abcd",4);
    assert(send(remote,&p,PB_HEADER+p.size,0) == (ssize_t)(PB_HEADER+p.size));
    handle_request(&s,&peer);
    assert(s.input_size == PB_INPUT_LIMIT-3);
    struct pb_packet response;
    memcpy(&response,peer.head->data,peer.head->size);
    assert(response.type == PB_INPUT+PB_REPLY && response.error == EAGAIN);
    assert(s.input[PB_INPUT_LIMIT-1] == 0xa7 && s.input[0] == 0xa7 && s.input[1] == 0xa7);
    peer_close(&peer); close(remote);
    pair(&peer,&remote);
    p.size=3;
    assert(send(remote,&p,PB_HEADER+p.size,0) == (ssize_t)(PB_HEADER+p.size));
    handle_request(&s,&peer);
    assert(s.input_size == PB_INPUT_LIMIT);
    memcpy(&response,peer.head->data,peer.head->size);
    assert(response.error == 0);
    assert(s.input[PB_INPUT_LIMIT-1]=='a' && s.input[0]=='b' && s.input[1]=='c');
    peer_close(&peer); close(remote); free(s.input);
    puts("PASS input queue: exact capacity, EAGAIN atomicity, wrapped tail");
}

static void output_queue(void)
{
    struct pb_peer peer;
    int remote;
    pair(&peer,&remote);
    unsigned char data[PB_CHUNK] = {0};
    /* Fill the queue to exactly PB_QUEUE, including protocol headers. */
    for (int i=0;i<15;++i) assert(queue(&peer,PB_OUTPUT,0,i,data,sizeof data)==0);
    size_t final = PB_QUEUE-peer.queued-PB_HEADER;
    assert(final <= PB_CHUNK);
    assert(queue(&peer,PB_OUTPUT,0,15,data,final)==0);
    assert(peer.queued == PB_QUEUE && peer.fd >= 0);
    assert(queue(&peer,PB_OUTPUT,0,16,data,1)<0);
    assert(peer.fd == -1 && peer.queued == 0 && !peer.head && !peer.tail);
    close(remote);
    puts("PASS output queue: headers included, exact capacity, disconnect frees queue");
}

static void authentication(void)
{
    char directory[]="/tmp/sol-pb-native-XXXXXX";
    assert(mkdtemp(directory));
    struct sockaddr_un address={.sun_family=AF_UNIX};
    snprintf(address.sun_path,sizeof address.sun_path,"%s/sock",directory);
    struct pb_server s={0};
    for(int i=0;i<PB_CLIENTS;++i)s.peers[i].fd=-1;
    s.listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    assert(s.listener>=0);
    assert(bind(s.listener,(struct sockaddr *)&address,sizeof address)==0);
    assert(listen(s.listener,4)==0);
    for(int bad=0;bad<=1;++bad) {
        int client=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
        assert(client>=0 && connect(client,(struct sockaddr *)&address,sizeof address)==0);
        foreign_uid=bad;
        accept_peers(&s);
        assert((s.peers[0].fd>=0) == !bad);
        if(!bad)peer_close(&s.peers[0]);
        else {
            unsigned char byte;
            assert(recv(client,&byte,1,0)==0);
        }
        close(client);
    }
    close(s.listener); assert(unlink(address.sun_path)==0); assert(rmdir(directory)==0);
    puts("PASS credentials: actual accept path with same and injected foreign UID");
}

int main(void)
{
    input_queue(); output_queue(); authentication();
    return 0;
}
