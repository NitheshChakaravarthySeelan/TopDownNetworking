#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "25"
#define BUF_SIZE 1024

/**
 * PORT 25
 * COMMAND HELO, MAIL FROM, RCPT TO, DATA, QUIT
 * RESPONSE 220: SERVICE READY, 250: OK, 354: START MAIL INPUT
 * | Client                                  | Server Response                  |
| --------------------------------------- | -------------------------------- |
| (connect)                               | 220 smtp.example.com ESMTP ready |
| HELO mydomain.com                       | 250 Hello mydomain.com           |
| MAIL FROM:[me@domain](mailto:me@domain) | 250 OK                           |
| RCPT TO:[you@domain](mailto:you@domain) | 250 OK                           |
| DATA                                    | 354 Start mail input             |
| [message body]                          | 250 OK                           |
| QUIT                                    | 221 Bye                          |

 */
// Helper function to receive server response
void recv_response(int sockfd) {
	char buf[BUF_SIZE];
	ssize_t numbytes;

	numbytes = recv(sockfd, buf, sizeof(buf)-1, 0);

	if (numbytes == -1) {
		perror("recv");
		exit(1);
	}

	buf[numbytes] = '\0';
	printf("%s", buf);
}

// Helper function to send command
void send_command(int sockfd, const char *cmd) {
	ssize_t bytes_sent = send(sockfd, cmd, strlen(cmd), 0);
	if (bytes_sent == -1) {
		perror("send");
		exit(1);
	}

	printf("C: %s", cmd);
}

int main(int argc, char *argv[]) {
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <SMTP server> <from email> <to email>\n", argv[0]);
		exit(1);
	}

	const char *server = argv[1];
	const char *from_email = argv[2];
	const char *to_email = argv[3];

	struct addrinfo hints, *res, *p;
	int sockfd;
	int rv;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(server, PORT, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	for (p=res; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1){
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			continue;
		}

		break;
	}

	if (p==NULL) {
		fprintf(stderr, "Failed to connect\n");
		return 1;
	}

	freeaddrinfo(res);

	// 1. Receive server greeting
    recv_response(sockfd);

    // 2. Send HELO
    char cmd[BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "HELO mydomain.com\r\n");
    send_command(sockfd, cmd);
    recv_response(sockfd);

    // 3. MAIL FROM
    snprintf(cmd, sizeof(cmd), "MAIL FROM:<%s>\r\n", from_email);
    send_command(sockfd, cmd);
    recv_response(sockfd);

    // 4. RCPT TO
    snprintf(cmd, sizeof(cmd), "RCPT TO:<%s>\r\n", to_email);
    send_command(sockfd, cmd);
    recv_response(sockfd);

    // 5. DATA
    snprintf(cmd, sizeof(cmd), "DATA\r\n");
    send_command(sockfd, cmd);
    recv_response(sockfd); // should be 354 Start mail input

    // 6. Message body
    snprintf(cmd, sizeof(cmd), "Subject: Test Email\r\n"
                               "From: %s\r\n"
                               "To: %s\r\n"
                               "\r\n"
                               "Hello, this is a test SMTP message!\r\n"
                               ".\r\n", from_email, to_email);
    send_command(sockfd, cmd);
    recv_response(sockfd); // should be 250 OK

    // 7. QUIT
    snprintf(cmd, sizeof(cmd), "QUIT\r\n");
    send_command(sockfd, cmd);
    recv_response(sockfd); // should be 221 Bye

    close(sockfd);
    return 0;
}
