#include "server_config.h"
#include "fsm.h"
#include "utils.h"
#include <stdio.h>
#include <time.h>

void push_work_back_into_queue(struct cracking_context *crack_ctx, uint64_t start, uint64_t remaining);
bool pop_next_work_chunk(struct cracking_context *ctx, uint64_t *out_start, uint64_t *out_len);
int  send_hash_to_worker(worker_state *ws, struct cracking_context *crack_ctx, struct fsm_error *err);

int socket_create(int domain, int type, int protocol, struct fsm_error *err)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if (sockfd == -1)
    {
        SET_ERROR(err, strerror(errno));
        return -1;
    }

    return sockfd;
}

int start_listening(int sockfd, int backlog, struct fsm_error *err)
{
    if (listen(sockfd, backlog) == -1)
    {
        SET_ERROR(err, strerror(errno));

        return -1;
    }

    return 0;
}

int socket_accept_connection(int sockfd, struct fsm_error *err)
{
    struct sockaddr client_addr;
    socklen_t       client_addr_len;

    client_addr_len = sizeof(client_addr);
    int client_fd;

    errno     = 0;
    client_fd = accept(sockfd, &client_addr, &client_addr_len);

    if (client_fd == -1)
    {
        if (errno != EINTR)
        {
            perror("Error in connecting to client.");
        }
        SET_ERROR(err, strerror(errno));

        return -1;
    }

    return client_fd;
}

int handle_new_client(int sockfd, int **client_sockets, nfds_t *max_clients, struct fsm_error *err)
{
    int client_sockfd;

    client_sockfd = socket_accept_connection(sockfd, err);
    if (client_sockfd == -1)
        return -1;

    (*max_clients)++;
    int *tmp = realloc(*client_sockets, sizeof(int) * (*max_clients));
    if (!tmp)
    {
        perror("Realloc error");
        (*max_clients)--;
        socket_close(client_sockfd, err);
        return -1;
    }

    *client_sockets                       = tmp;
    (*client_sockets)[(*max_clients) - 1] = client_sockfd;

    printf("Connected to client: %d\n\n", client_sockfd);

    return client_sockfd;
}

void close_clients(int *client_sockets, worker_state **client_states, nfds_t max_clients, struct fsm_error *err)
{
    for (size_t i = 0; i < max_clients; i++)
    {
        if (client_sockets[i] > 0)
            socket_close(client_sockets[i], err);

        if (client_states[i])
            free(client_states[i]);
    }
}

int socket_close(int sockfd, struct fsm_error *err)
{
    if (close(sockfd) == -1)
    {
        SET_ERROR(err, strerror(errno));
        return -1;
    }

    return 0;
}

int send_hash_to_worker(worker_state *ws, struct cracking_context *crack_ctx, struct fsm_error *err)
{
    char buffer[512];

    int n = snprintf(buffer, sizeof(buffer), "HASH %s\n", crack_ctx->hash);

    if (n <= 0)
    {
        SET_ERROR(err, "Failed to format HASH message");
        return -1;
    }

    if (send(ws->sockfd, buffer, n, 0) < 0)
    {
        SET_ERROR(err, "Failed to send HASH to worker");
        return -1;
    }

    printf("[SERVER] Sent HASH to worker(fd=%d)\n", ws->sockfd);

    return 0;
}

int polling(int sockfd, struct pollfd **file_descriptors, nfds_t *max_clients, int **client_sockets,
            worker_state ***client_states, struct cracking_context *crack_ctx, struct fsm_error *err)
{
    int            num_ready;
    struct pollfd *temp_fds;

    temp_fds = (struct pollfd *)realloc((*file_descriptors), (*max_clients + 2) * sizeof(struct pollfd));
    if (!temp_fds)
    {
        SET_ERROR(err, "Error reallocing for fd's in polling");
        return -1;
    }

    (*file_descriptors) = temp_fds;

    (*file_descriptors)[0].fd      = sockfd;
    (*file_descriptors)[0].events  = POLLIN;
    (*file_descriptors)[0].revents = 0;

    for (uint32_t i = 0; i < *max_clients; i++)
    {
        int tempfd;

        tempfd = (*client_sockets)[i];

        (*file_descriptors)[i + 1].fd      = tempfd;
        (*file_descriptors)[i + 1].events  = POLLIN;
        (*file_descriptors)[i + 1].revents = 0;
        (*client_states)[i]->sockfd        = tempfd;
    }

    num_ready = poll((*file_descriptors), *max_clients + 1, 1000);

    if (num_ready < 0)
    {
        if (errno == EINTR)
            return 0;

        SET_ERROR(err, "Polling error");
        return -1;
    }

    if ((*file_descriptors)[0].revents & POLLIN)
    {
        int newfd;

        newfd = handle_new_client(sockfd, &*client_sockets, &*max_clients, err);

        if (newfd >= 0)
        {
            worker_state *ws;

            *client_states                     = realloc(*client_states, (*max_clients) * sizeof(worker_state *));
            (*client_states)[*max_clients - 1] = calloc(1, sizeof(worker_state));

            ws             = (*client_states)[*max_clients - 1];
            ws->sockfd     = newfd;
            ws->alive      = 1;
            ws->assigned   = 0;
            ws->last_heard = time(NULL);
            ws->recv_len   = 0;

            send_hash_to_worker(ws, crack_ctx, err);

            num_ready--;
        }
    }

    for (uint32_t i = 0; i < *max_clients; i++)
    {
        worker_state *ws;
        int           sd;

        ws = (*client_states)[i];
        if (!ws->alive)
            continue;

        if ((*file_descriptors)[i + 1].revents & POLLIN)
        {
            sd = (*client_sockets)[i];

            if (process_client_message(sd, ws, crack_ctx, err) == -1)
            {
                if (!crack_ctx->found)
                    reclaim_and_redistribute(ws, crack_ctx);

                handle_client_disconnect(i, client_sockets, client_states, max_clients);
                continue;
            }

            ws->last_heard = time(NULL);
            num_ready--;
        }

        if (time(NULL) - ws->last_heard > ws->timeout_seconds)
        {
            printf("Worker timed out! Reassigning work.\n");
            reclaim_and_redistribute(ws, crack_ctx);
            handle_client_disconnect(i, client_sockets, client_states, max_clients);
        }
    }

    return 0;
}

int assign_work_to_client(struct worker_state *ws, struct cracking_context *crack_ctx, struct fsm_error *err)
{
    if (crack_ctx->found)
    {
        const char *msg = "STOP\n";
        send(ws->sockfd, msg, strlen(msg), 0);
        return 1;
    }

    uint64_t start = 0;
    uint64_t len   = 0;

    pop_next_work_chunk(crack_ctx, &start, &len);

    ws->start_index           = start;
    ws->work_size             = len;
    ws->end_index             = start + len - 1;
    ws->last_checkpoint_index = start;
    ws->assigned              = 1;
    ws->started_at            = time(NULL);
    ws->last_heard            = ws->started_at;
    ws->checkpoint_interval   = crack_ctx->checkpoint;
    ws->timeout_seconds       = crack_ctx->timeout;

    char buffer[256];
    int  n = snprintf(buffer, sizeof(buffer),
                      "WORK %" PRIu64 " %" PRIu64 " %" PRIu64 " %u\n",
                      ws->start_index,
                      ws->work_size,
                      ws->checkpoint_interval,
                      ws->timeout_seconds);

    ssize_t sent = send(ws->sockfd, buffer, n, 0);
    if (sent < 0)
    {
        SET_ERROR(err, "assign_work_to_client(): send() failed");
        return -1;
    }

    printf("[SERVER] Assigned worker(fd=%d) work: start=%" PRIu64
           ", size=%" PRIu64 ", checkpoint=%" PRIu64 ", timeout=%u\n",
           ws->sockfd, ws->start_index, ws->work_size,
           ws->checkpoint_interval, ws->timeout_seconds);

    return 0;
}

int process_client_message(int sd, worker_state *ws,
                           struct cracking_context *crack_ctx,
                           struct fsm_error        *err)
{
    char    temp[256];
    ssize_t n = recv(sd, temp, sizeof(temp), 0);

    if (n <= 0)
        return -1;

    if (ws->recv_len + n >= RECV_BUF_SIZE)
    {
        SET_ERROR(err, "Worker recv buffer overflow");
        return -1;
    }

    memcpy(ws->recv_buf + ws->recv_len, temp, n);
    ws->recv_len += n;

    size_t start = 0;

    for (size_t i = 0; i < ws->recv_len; i++)
    {
        if (ws->recv_buf[i] == '\n')
        {
            ws->recv_buf[i] = '\0';

            char *msg = ws->recv_buf + start;
            if (handle_single_message(sd, ws, crack_ctx, msg, err) != 0)
                return -1;

            start = i + 1;
        }
    }

    if (start < ws->recv_len)
    {
        size_t leftover = ws->recv_len - start;
        memmove(ws->recv_buf, ws->recv_buf + start, leftover);
        ws->recv_len = leftover;
    }
    else
    {
        ws->recv_len = 0;
    }

    return 0;
}

int handle_single_message(int sd, worker_state *ws, struct cracking_context *crack_ctx,
                          const char *buffer, struct fsm_error *err)
{
    if (strncmp(buffer, "READY", 5) == 0)
    {
        printf("[SERVER] Worker %d is READY\n", sd);

        if (!crack_ctx->found)
        {
            if (assign_work_to_client(ws, crack_ctx, err) == -1)
                return -1;
        }

        return 0;
    }
    else if (strncmp(buffer, "CHECKPOINT ", 11) == 0)
    {
        uint64_t idx = strtoull(buffer + 11, NULL, 10);
        if (idx < ws->start_index || idx > ws->end_index)
        {
            SET_ERROR(err, "Checkpoint out of range");
            return -1;
        }

        time_t now = time(NULL);

        crack_ctx->total_secs += now - ws->last_heard;

        ws->last_checkpoint_index = idx;
        ws->last_heard            = now;

        printf("[SERVER] Worker %d checkpoint → %" PRIu64 "\n", sd, idx);
        return 0;
    }
    else if (strncmp(buffer, "FOUND ", 6) == 0)
    {
        const char *pw = buffer + 6;

        time_t now = time(NULL);

        crack_ctx->total_secs += now - ws->last_heard;

        printf("[SERVER] WORKER %d FOUND PASSWORD: %s in %ld seconds.\n", sd, pw, now - ws->started_at);

        crack_ctx->found = 1;
        strncpy(crack_ctx->password, pw, sizeof(crack_ctx->password));

        return 1;
    }
    else if (strncmp(buffer, "DONE", 4) == 0)
    {
        time_t now = time(NULL);

        crack_ctx->total_secs += now - ws->last_heard;

        ws->duration_secs = now - ws->started_at;

        printf("[SERVER] Worker %d finished its work in %ld seconds.\n", sd, ws->duration_secs);

        ws->assigned = 0;

        if (!crack_ctx->found)
        {
            if (assign_work_to_client(ws, crack_ctx, err) == -1)
                return -1;
        }

        return 0;
    }
    else
    {
        SET_ERROR(err, "Invalid message from worker");
        return -1;
    }
}

void handle_client_disconnect(uint32_t i, int **client_sockets, worker_state ***client_states, nfds_t *max_clients)
{
    int fd = (*client_sockets)[i];
    close(fd);

    free((*client_states)[i]);

    for (uint32_t j = i; j < (*max_clients) - 1; j++)
    {
        (*client_sockets)[j] = (*client_sockets)[j + 1];
        (*client_states)[j]  = (*client_states)[j + 1];
    }

    (*max_clients)--;

    if (*max_clients == 0)
    {
        free(*client_sockets);
        free(*client_states);
        *client_sockets = NULL;
        *client_states  = NULL;
        return;
    }

    *client_sockets = realloc(*client_sockets, *max_clients * sizeof(int));
    *client_states  = realloc(*client_states, *max_clients * sizeof(worker_state *));
}

void push_work_back_into_queue(struct cracking_context *crack_ctx, uint64_t start, uint64_t remaining)
{
    if (remaining == 0)
        return;

    size_t new_len = crack_ctx->queue_len + 1;

    work_chunk *tmp = realloc(crack_ctx->queue, new_len * sizeof(work_chunk));
    if (!tmp)
    {
        perror("realloc failed in push_work_back_into_queue");
        return;
    }

    crack_ctx->queue = tmp;

    crack_ctx->queue[new_len - 1].start = start;
    crack_ctx->queue[new_len - 1].len   = remaining;

    crack_ctx->queue_len = new_len;
}

void reclaim_and_redistribute(worker_state *ws, struct cracking_context *crack_ctx)
{
    uint64_t start = ws->last_checkpoint_index;
    uint64_t end   = ws->end_index;

    if (start > end)
    {
        return;
    }

    uint64_t remaining = (end - start) + 1;

    printf("[SERVER] Reclaiming %" PRIu64 " units of unfinished work from %d "
           "(%" PRIu64 " -> %" PRIu64 ")\n",
           remaining, ws->sockfd, start, end);

    push_work_back_into_queue(crack_ctx, start, remaining);

    ws->assigned = false;
    ws->alive    = false;
}

bool pop_next_work_chunk(struct cracking_context *ctx, uint64_t *out_start, uint64_t *out_len)
{
    if (ctx->queue_len > 0)
    {
        size_t last = ctx->queue_len - 1;

        *out_start = ctx->queue[last].start;
        *out_len   = ctx->queue[last].len;

        ctx->queue_len--;

        if (ctx->queue_len == 0)
        {
            free(ctx->queue);
            ctx->queue = NULL;
        }
        else
        {
            ctx->queue = realloc(ctx->queue, ctx->queue_len * sizeof(work_chunk));
        }

        return true;
    }

    *out_start = ctx->index;
    *out_len   = ctx->work_size;

    ctx->index += ctx->work_size;

    return true;
}

int convert_address(const char *address, struct sockaddr_storage *addr, in_port_t port, struct fsm_error *err)
{
    memset(addr, 0, sizeof(*addr));
    char      addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void     *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if (inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        // IPv4 server_addr
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr               = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
        addr->ss_family     = AF_INET;
    }
    else if (inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr                = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
        addr->ss_family      = AF_INET6;
    }
    else
    {
        char message[90];
        snprintf(message, sizeof(message), "Address family not supported for IP address: %s", address);

        SET_ERROR(err, message);
        return -1;
    }

    return 0;
}

int socket_bind(int sockfd, struct sockaddr_storage *addr, struct fsm_error *err)
{
    char *ip_address;
    char *port;

    ip_address = safe_malloc(sizeof(char) * NI_MAXHOST, err);
    port       = safe_malloc(sizeof(char) * NI_MAXSERV, err);

    if (get_sockaddr_info(addr, &ip_address, &port, err) != 0)
    {
        free(ip_address);
        free(port);

        return -1;
    }

    printf("binding to: %s:%s\n", ip_address, port);

    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(sockfd, (struct sockaddr *)addr, size_of_address(addr)) == -1)
    {
        SET_ERROR(err, strerror(errno));
        free(ip_address);
        free(port);

        return -1;
    }

    printf("Bound to socket: %s:%s\n", ip_address, port);

    free(ip_address);
    free(port);

    return 0;
}

socklen_t size_of_address(struct sockaddr_storage *addr)
{
    return addr->ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

int get_sockaddr_info(struct sockaddr_storage *addr, char **ip_address, char **port, struct fsm_error *err)
{
    char      temp_ip[NI_MAXHOST];
    char      temp_port[NI_MAXSERV];
    socklen_t ip_size;
    int       result;

    ip_size = sizeof(*addr);
    result  = getnameinfo((struct sockaddr *)addr, ip_size, temp_ip, sizeof(temp_ip), temp_port,
                          sizeof(temp_port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (result != 0)
    {
        SET_ERROR(err, strerror(errno));
        return -1;
    }

    strcpy(*ip_address, temp_ip);
    strcpy(*port, temp_port);

    return 0;
}
