#pragma once

#define CMD_NAMED_PIPE L"\\\\.\\pipe\\cppcryptfs_cmd"

#define CMD_NAMED_PIPE_BUFSIZE 2048

bool StartNamedPipeServer();