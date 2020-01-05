#pragma once

#define CMD_NAMED_PIPE L"\\\\.\\pipe\\cppcryptfs_cmd"

#define CMD_NAMED_PIPE_BUFSIZE 2048 // max command line length

#define CMD_PIPE_VERSION_STR L"CPPCRYPTFS_CMD_PIPE_0001"
#define CMD_PIPE_VERSION_LEN (_countof(CMD_PIPE_VERSION_STR)-1)

#define CMD_PIPE_SUCCESS 0
#define CMD_PIPE_ERROR   1
#define CMD_PIPE_RESPONSE_LENGTH 7
#define CMD_PIPE_SUCCESS_STR L"SUCCESS"
#define CMD_PIPE_ERROR_STR   L"ERROR  " // pad to 7 characters

#define CMD_PIPE_MAX_ARGS_LEN 4096
#define CMD_PIPE_MAX_ARGS_LEN_USER 4000 // show this limit to the user