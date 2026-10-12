/*
 * Minimal command line editing
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "edit.h"


#define CMD_BUF_LEN 4096
static char cmdbuf[CMD_BUF_LEN];
static int cmdbuf_pos = 0;
static const char *ps2 = NULL;

static void *edit_cb_ctx;
static void (*edit_cmd_cb)(void *ctx, char *cmd);
static void (*edit_eof_cb)(void *ctx);


static void edit_read_char(int sock, void *eloop_ctx, void *sock_ctx)
{
	int c;
	unsigned char buf[1];
	int res;

	res = read(sock, buf, 1);/*读取一个字符*/
	if (res < 0)
		perror("read");
	if (res <= 0) {
		/*达到结尾/读取出错，调用eof回调*/
		edit_eof_cb(edit_cb_ctx);
		return;
	}
	c = buf[0];

	if (c == '\r' || c == '\n') {
		/*遇到换行符，命令缓存结束*/
		cmdbuf[cmdbuf_pos] = '\0';
		cmdbuf_pos = 0;
		edit_cmd_cb(edit_cb_ctx, cmdbuf);/*执行cmd回调*/
		printf("%s> ", ps2 ? ps2 : "");/*显示提示符*/
		fflush(stdout);
		return;
	}

	if (c == '\b') {
		/*遇到退格键，命令缓存内容退一格*/
		if (cmdbuf_pos > 0)
			cmdbuf_pos--;
		return;
	}

	/*c基本为可显示字符，缓存到cmdbuf*/
	if (c >= 32 && c <= 255) {
		if (cmdbuf_pos < (int) sizeof(cmdbuf) - 1) {
			cmdbuf[cmdbuf_pos++] = c;
		}
	}
}


int edit_init(void (*cmd_cb/*cmd执行的回调*/)(void *ctx, char *cmd),
	      void (*eof_cb/*出错/到达文件结尾时执行的回调*/)(void *ctx),
	      char ** (*completion_cb/*未使用*/)(void *ctx, const char *cmd, int pos),
	      void *ctx, const char *history_file, const char *ps/*提示符*/)
{
	edit_cb_ctx = ctx;
	edit_cmd_cb = cmd_cb;
	edit_eof_cb = eof_cb;
	/*注册stdin对应的读取回调*/
	eloop_register_read_sock(STDIN_FILENO, edit_read_char/*读取stdin,处理输入内容*/, NULL, NULL);
	ps2 = ps;

	printf("%s> ", ps2 ? ps2 : "");/*显示提示符*/
	fflush(stdout);

	return 0;
}


void edit_deinit(const char *history_file,
		 int (*filter_cb)(void *ctx, const char *cmd))
{
	eloop_unregister_read_sock(STDIN_FILENO);
}


void edit_clear_line(void)
{
}


void edit_redraw(void)
{
	cmdbuf[cmdbuf_pos] = '\0';
	printf("\r> %s", cmdbuf);
}
