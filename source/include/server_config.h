#ifndef CLIENT_SERVER_CONFIG_H
#define CLIENT_SERVER_CONFIG_H

#include "fsm.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int       socket_create(int domain, int type, int protocol, struct fsm_error *err);
int       start_listening(int sockfd, int backlog, struct fsm_error *err);
int       socket_accept_connection(int sockfd, struct fsm_error *err);
int       socket_close(int sockfd, struct fsm_error *err);
int       socket_bind(int sockfd, struct sockaddr_storage *addr, struct fsm_error *err);
void      close_clients(int *client_sockets, worker_state **client_states, nfds_t max_clients, struct fsm_error *err);
socklen_t size_of_address(struct sockaddr_storage *addr);
int       handle_new_client(int sockfd, int **client_sockets, nfds_t *max_clients, struct fsm_error *err);
int       get_sockaddr_info(struct sockaddr_storage *addr, char **ip_address, char **port, struct fsm_error *err);
void     *safe_malloc(uint32_t size, struct fsm_error *err);
int       assign_work_to_client(struct worker_state *ws, struct cracking_context *crack_ctx, struct fsm_error *err);
int       process_client_message(int sd, worker_state *ws, struct cracking_context *crack_ctx, struct fsm_error *err);
int       handle_single_message(int sd, worker_state *ws, struct cracking_context *crack_ctx,
                                const char *buffer, struct fsm_error *err);
void      handle_client_disconnect(uint32_t i, int **client_sockets, worker_state ***client_states, nfds_t *max_clients);
void      reclaim_and_redistribute(worker_state *ws, struct cracking_context *crack_ctx);
int       convert_address(const char *address, struct sockaddr_storage *addr, in_port_t port,
                          struct fsm_error *err);
int       polling(int sockfd, struct pollfd **file_descriptors, nfds_t *max_clients, int **client_sockets,
                  worker_state ***client_states, struct cracking_context *crack_ctx, struct fsm_error *err);

#endif // CLIENT_SERVER_CONFIG_H
