/*
 * WPA Supplicant - ASCII passphrase to WPA PSK tool
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <termios.h>

#include "common.h"
#include "crypto/sha1.h"


int main(int argc, char *argv[])
{
	struct termios term;
	unsigned char psk[32];
	int i;
	char *ssid, *passphrase, buf[64], *pos;
	size_t len;

	if (argc < 2) {
		printf("usage: wpa_passphrase <ssid> [passphrase]\n"
			"\nIf passphrase is left out, it will be read from "
			"stdin\n");
		return 1;
	}

	ssid = argv[1];/*提供连接用的SSID*/

	if (argc > 2) {
		passphrase = argv[2];/*连接用的密码*/
	} else {
		bool ctrl_echo;

		/*要么从stdin上读取*/
		fprintf(stderr, "# reading passphrase from stdin\n");
		if (tcgetattr(STDIN_FILENO, &term) < 0) {
			perror("tcgetattr");
			return 1;
		}
		ctrl_echo = term.c_lflag & ECHO;
		term.c_lflag &= ~ECHO;
		if (ctrl_echo && tcsetattr(STDIN_FILENO, TCSANOW, &term) < 0) {
			perror("tcsetattr:error disabling echo");
			return 1;
		}
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			fprintf(stderr, "Failed to read passphrase\n");
			return 1;
		}
		term.c_lflag |= ECHO;
		if (ctrl_echo && tcsetattr(STDIN_FILENO, TCSANOW, &term) < 0) {
			perror("tcsetattr:error enabling echo");
			return 1;
		}
		buf[sizeof(buf) - 1] = '\0';
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\r' || *pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		passphrase = buf;
	}

	len = os_strlen(passphrase);
	if (len < 8 || len > 63) {
		/*密码必须大于8且小于63*/
		fprintf(stderr, "Passphrase must be 8..63 characters\n");
		return 1;
	}

	/*排除掉不支持的字符*/
	if (has_ctrl_char((u8 *) passphrase, len)) {
		fprintf(stderr, "Invalid passphrase character\n");
		return 1;
	}

	/*恰好走src/crypto/crypto_openssl.c文件*/
	if (pbkdf2_sha1(passphrase, (u8 *) ssid, os_strlen(ssid), 4096, psk, 32)
	    != 0) {
		fprintf(stderr, "Error in pbkdf2_sha1()\n");
		return 1;
	}

	printf("network={\n");
	printf("\tssid=\"%s\"\n", ssid);
	printf("\t#psk=\"%s\"\n", passphrase);
	printf("\tpsk=");
	for (i = 0; i < 32; i++)
		printf("%02x", psk[i]);
	printf("\n");
	printf("}\n");

	return 0;
}
