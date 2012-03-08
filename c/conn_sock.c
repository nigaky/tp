#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>


#define PORT 9000
#define LOOPS 10

void *client_work(void *arg)
{
	int i, fd;
	long num = (long)arg;
	struct sockaddr_in caddr;
	struct hostent *h;

	h = gethostbyname("localhost");
	if (!h) {
		perror("gethostbyname");
		exit(1);
	}
	caddr.sin_family        = PF_INET;
	memcpy(&caddr.sin_addr.s_addr, h->h_addr, sizeof(h->h_length));
	caddr.sin_port          = htons(PORT + num + 1);



	for (i=0;i<LOOPS;i++) {
		if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			return NULL;
		}

		if (connect(fd, (struct sockaddr *)&caddr, sizeof(caddr))) {
			perror("connect");
			return NULL;
		}
		close(fd);
	}
	return NULL;
}

int send_op(int op, int op_fd)
{
	int ret;

	ret = write(op_fd, &op, sizeof(op));
	if (ret != sizeof(op)) {
		fprintf(stderr, "Error on send_op()\n");
		return -1;
	}
	return 0;
}

/* init opperation sock and return fd */
int init_op_sock_client(void)
{
	int op_fd;
	struct hostent *h;
	struct sockaddr_in caddr;

	if ((op_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	h = gethostbyname("localhost");
	if (!h) {
		perror("gethostbyname");
		exit(1);
	}
	caddr.sin_family        = PF_INET;
	memcpy(&caddr.sin_addr.s_addr, h->h_addr, sizeof(h->h_length));
	caddr.sin_port          = htons(PORT);

	if (connect(op_fd, (struct sockaddr *)&caddr, sizeof(caddr))) {
		perror("connect");
		exit(1);
	}
	return op_fd;
}

/* client side */
void run_client(void)
{
	int op_fd;
	int nr_threads;
	pthread_t *p;
	long i;

	op_fd = init_op_sock_client();

	nr_threads = 2;

	p = malloc(sizeof(pthread_t) * nr_threads);
	if (!p) {
		perror("malloc");
		exit(1);
	}

	send_op(nr_threads, op_fd);

	/* create server worker */
	for (i=0;i<nr_threads;i++) {
		pthread_create(&p[i], NULL, client_work, (void *)i);
	}

	/* wait for client workers */
	for (i=0;i<nr_threads;i++) {
		pthread_join(p[i], NULL);
	}

	send_op(-1, op_fd);
}


/* server side */
void *server_work(void *arg)
{
	long num = (long)arg;
	int fd, ret, conn_fd;
	char buf[64];
	struct sockaddr_in addr;
	int len;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return NULL;
	}

	addr.sin_family        = PF_INET;
	addr.sin_addr.s_addr   = INADDR_ANY;
	addr.sin_port          = htons(PORT + num + 1);
	len = sizeof(addr);
	if (bind(fd, (struct sockaddr *)&addr, (socklen_t)len) < 0) {
		perror("bind");
		return NULL;
	}

	if (listen(fd, SOMAXCONN) < 0) {
		perror("listen");
		return NULL;
	}

	while (1) {
		if ((conn_fd = accept(fd, (struct sockaddr *)&addr, (socklen_t *)&len)) < 0) {
			perror("accept");
			exit(1);
		}

		ret = read(fd, buf, sizeof(buf));
		if (ret != 0) {
			fprintf(stderr, "read some bytes?\n");
			return NULL;
		}
		close(conn_fd);
	}
	return NULL;
}

/* handle client operation */
int recv_op(int op_fd)
{
	int op, ret;
	ret = read(op_fd, &op, sizeof(op));

	if (ret < 0) {
		perror("op read");
		exit(1);
	} else if (ret == 0) {
		/* EOF */
		fprintf(stderr, "Connection closed\n");
		exit(1);
	}
	return op;
}

/* init opperation sock and return fd */
int init_op_sock_server(void)
{
	int op_fd, conn_fd;
	struct sockaddr_in addr;
	int len;

	if ((op_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	addr.sin_family        = PF_INET;
	addr.sin_addr.s_addr   = INADDR_ANY;
	addr.sin_port          = htons(PORT);
	len = sizeof(addr);
	if (bind(op_fd, (struct sockaddr *)&addr, (socklen_t)len) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(op_fd, SOMAXCONN) < 0) {
		perror("listen");
		exit(1);
	}

	if ((conn_fd = accept(op_fd, (struct sockaddr *)&addr, (socklen_t *)&len)) < 0) {
		perror("accept");
		exit(1);
	}
	close(op_fd);
	return conn_fd;
}

void run_server(void)
{
	long i;
	int op_fd;
	int nr_threads;
	pthread_t *p;

	op_fd = init_op_sock_server();
	while(1) {
		nr_threads = recv_op(op_fd);
		p = malloc(sizeof(pthread_t) * nr_threads);
		if (!p) {
			perror("malloc");
			exit(1);
		}

		/* create server worker */
		for (i=0;i<nr_threads;i++) {
			pthread_create(&p[i], NULL, server_work, (void *)i);
		}

		/* assume recieving cancel operation */
		recv_op(op_fd);
		for (i=0;i<nr_threads;i++) {
			pthread_cancel(p[i]);
		}
		for (i=0;i<nr_threads;i++) {
			pthread_join(p[i], NULL);
		}
		/* all workers are finished */

		free(p);
	}
	close(op_fd);
}

int main(int argc, char **argv)
{

	if (argc == 1) {
		printf("Usage: ./conn_sock [-s] [host]\n");
		exit(0);
	}

	if (strcmp(argv[1], "-s") == 0)
		run_server();
	else
		run_client();

	return 0;
}
