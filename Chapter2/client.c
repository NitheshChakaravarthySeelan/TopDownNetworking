#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT "80"

int main(int argc, char *argv[]) {
	struct addrinfo hints, *res, *p;
	int sockfd;
	int numbytes;
	char buf[4096];
	ssize_t bytes_sent;
	const char *message =
    				"GET / HTTP/1.1\r\n"
    				"Host: google.com\r\n"
    				"Connection: close\r\n"
    				"\r\n";

	if (argc != 2) {
		fprintf(stderr, "usage: client hostname\n");
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(argv[1],PORT, &hints, &res) != 0) {
		perror("getaddrinfo");
		return 2;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1 ) {
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			continue;
		}

		break;
	}

	freeaddrinfo(res);

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect");
		return 2;
	}

	bytes_sent = send(sockfd, message, strlen(message),0);

	if (bytes_sent == -1) {
		perror("Error sending message");
		exit(1);
	}

	FILE *fp = fopen("response.txt", "w");
	if (!fp) {
		perror("fopen");
		exit(1);
	}

	while ((numbytes = recv(sockfd, buf, sizeof(buf) - 1, 0)) > 0) {
		fwrite(buf, 1, numbytes, fp);
	}

	fclose(fp);
	close(sockfd);

	printf("Response saved to response.txt\n");
	return 0;
}
