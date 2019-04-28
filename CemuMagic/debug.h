#pragma once

#include <Windows.h>
#include <stdarg.h>
#include <stdio.h>

static char dprintf_msg[66000];

void dprintf(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	*dprintf_msg = 0;
	auto len = vsnprintf_s(dprintf_msg, sizeof(dprintf_msg), format, args);
	for (; len; len--)
	{
		auto& ch = dprintf_msg[len - 1];
		if (ch == '\r' || ch == '\n')
			ch = '\0';
		else
			break;
	}
	OutputDebugStringA(dprintf_msg);
}

void dputs(const char* text)
{
	dprintf("%s\n", text);
}

#define DEBUGNAME "CemuMagic"

#define dlog() dprintf("[AppInitHook] [" DEBUGNAME "] [%u] " __FUNCTION__ "\n", GetCurrentProcessId())
#define dlogp(fmt, ...) dprintf("[AppInitHook] [" DEBUGNAME "] [%u] " __FUNCTION__ "(" fmt ")\n", GetCurrentProcessId(), __VA_ARGS__)