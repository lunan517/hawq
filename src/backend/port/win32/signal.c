/*-------------------------------------------------------------------------
 *
 * signal.c
 *	  Microsoft Windows Win32 Signal Emulation Functions
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/port/win32/signal.c,v 1.22 2009/01/01 17:23:46 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <libpq/pqsignal.h>

/*
 * These are exported for use by the UNBLOCKED_SIGNAL_QUEUE() macro.
 * pg_signal_queue must be volatile since it is changed by the signal
 * handling thread and inspected without any lock by the main thread.
 * pg_signal_mask is only changed by main thread so shouldn't need it.
 */
volatile int pg_signal_queue;
int			pg_signal_mask;

HANDLE		pgwin32_signal_event;
HANDLE		pgwin32_initial_signal_pipe = INVALID_HANDLE_VALUE;

/*
 * pg_signal_crit_sec is used to protect only pg_signal_queue. That is the only
 * variable that can be accessed from the signal sending threads!
 */
static CRITICAL_SECTION pg_signal_crit_sec;

static pqsigfunc pg_signal_array[PG_SIGNAL_COUNT];
static pqsigfunc pg_signal_defaults[PG_SIGNAL_COUNT];


/* Signal handling thread function */
static DWORD WINAPI pg_signal_thread(LPVOID param);
static BOOL WINAPI pg_console_handler(DWORD dwCtrlType);


/*
 * pg_usleep --- delay the specified number of microseconds, but
 * stop waiting if a signal arrives.
 *
 * This replaces the non-signal-aware version provided by src/port/pgsleep.c.
 */
void
pg_usleep(long microsec)
{
	if (WaitForSingleObject(pgwin32_signal_event,
							(microsec < 500 ? 1 : (microsec + 500) / 1000))
		== WAIT_OBJECT_0)
	{
	    // 调用 pgwin32_signal_event 处理过程
		pgwin32_dispatch_queued_signals();
		errno = EINTR;
		return;
	}
}


/* Initialization */
void
pgwin32_signal_initialize(void)
{
	int			i;
	HANDLE		signal_thread_handle;

	// 初始化临界区
	InitializeCriticalSection(&pg_signal_crit_sec);

	// port.h #define PG_SIGNAL_COUNT 32
	for (i = 0; i < PG_SIGNAL_COUNT; i++)
	{
		pg_signal_array[i] = SIG_DFL;
		pg_signal_defaults[i] = SIG_IGN;
	}
	pg_signal_mask = 0;
	pg_signal_queue = 0;

	/* Create the global event handle used to flag signals */
	// 在port/win32/signal.c的pg_usleep中判断是否有Event发生，并调用pgwin32_dispatch_queued_signals处理
	pgwin32_signal_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (pgwin32_signal_event == NULL)
		ereport(FATAL,
				(errmsg_internal("failed to create signal event: %d", (int) GetLastError())));

	/* Create thread for handling signals */
	// 创建线程，通过管道接收客户端信号
	signal_thread_handle = CreateThread(NULL, 0, pg_signal_thread, NULL, 0, NULL);
	if (signal_thread_handle == NULL)
		ereport(FATAL,
				(errmsg_internal("failed to create signal handler thread")));

	/* Create console control handle to pick up Ctrl-C etc */
	// 加载控制台关闭事件的勾子函数 pg_console_handler（激活SIGINT信号，并启动事件pgwin32_signal_event）
	if (!SetConsoleCtrlHandler(pg_console_handler, TRUE))
		ereport(FATAL,
				(errmsg_internal("failed to set console control handler")));
}

/*
 * Dispatch all signals currently queued and not blocked
 * Blocked signals are ignored, and will be fired at the time of
 * the sigsetmask() call.
 */
void
pgwin32_dispatch_queued_signals(void)
{
	int			i;

	// 进入临界区，加锁
	EnterCriticalSection(&pg_signal_crit_sec);
	while (UNBLOCKED_SIGNAL_QUEUE())
	{
		/* One or more unblocked signals queued for execution */
		int			exec_mask = UNBLOCKED_SIGNAL_QUEUE();

		for (i = 0; i < PG_SIGNAL_COUNT; i++)
		{
			if (exec_mask & sigmask(i))
			{
				/* Execute this signal */
				// pg_signal_array 中保存的是信号处理函数handle
				pqsigfunc	sig = pg_signal_array[i];

				if (sig == SIG_DFL)
					sig = pg_signal_defaults[i];
				pg_signal_queue &= ~sigmask(i);
				if (sig != SIG_ERR && sig != SIG_IGN && sig != SIG_DFL)
				{
					LeaveCriticalSection(&pg_signal_crit_sec);
					// 这里调用 pg_signal_array 中的处理函数handle
					sig(i);
					EnterCriticalSection(&pg_signal_crit_sec);
					break;		/* Restart outer loop, in case signal mask or
								 * queue has been modified inside signal
								 * handler */
				}
			}
		}
	}
	ResetEvent(pgwin32_signal_event);
	LeaveCriticalSection(&pg_signal_crit_sec);
}

/* signal masking. Only called on main thread, no sync required */
int
pqsigsetmask(int mask)
{
	int			prevmask;

	prevmask = pg_signal_mask;
	pg_signal_mask = mask;

	/*
	 * Dispatch any signals queued up right away, in case we have unblocked
	 * one or more signals previously queued
	 */
	pgwin32_dispatch_queued_signals();

	return prevmask;
}


/* signal manipulation. Only called on main thread, no sync required */
// 将处理函数的handler更新到对应的sigNum，保存在pg_signal_array中
pqsigfunc
pqsignal(int signum, pqsigfunc handler)
{
	pqsigfunc	prevfunc;

	if (signum >= PG_SIGNAL_COUNT || signum < 0)
		return SIG_ERR;
	prevfunc = pg_signal_array[signum];
	pg_signal_array[signum] = handler;
	return prevfunc;
}

/* Create the signal listener pipe for specified pid */
HANDLE
pgwin32_create_signal_listener(pid_t pid)
{
	char		pipename[128];
	HANDLE		pipe;

	snprintf(pipename, sizeof(pipename), "\\\\.\\pipe\\pgsignal_%u", (int) pid);

	pipe = CreateNamedPipe(pipename, PIPE_ACCESS_DUPLEX,
					   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
						   PIPE_UNLIMITED_INSTANCES, 16, 16, 1000, NULL);

	if (pipe == INVALID_HANDLE_VALUE)
		ereport(ERROR,
				(errmsg("could not create signal listener pipe for pid %d: error code %d",
						(int) pid, (int) GetLastError())));

	return pipe;
}


/*
 * All functions below execute on the signal handler thread
 * and must be synchronized as such!
 * NOTE! The only global variable that can be used is
 * pg_signal_queue!
 */


void
pg_queue_signal(int signum)
{
	if (signum >= PG_SIGNAL_COUNT || signum <= 0)
		return;

	// 多线程操作
    // 进入临界区/加锁
	EnterCriticalSection(&pg_signal_crit_sec);
	// port/win32.h  #define sigmask(sig) ( 1 << ((sig)-1) )
	pg_signal_queue |= sigmask(signum);
	// 退出临界区
	LeaveCriticalSection(&pg_signal_crit_sec);

	// 在port/win32/signal.c中pg_usleep中等待事件触发
	SetEvent(pgwin32_signal_event);
}

/* Signal dispatching thread */
// 接收客户端通过管道发来的信号，并处理
static DWORD WINAPI
pg_signal_dispatch_thread(LPVOID param)
{
	HANDLE		pipe = (HANDLE) param;
	BYTE		sigNum;
	DWORD		bytes;

	// 获得信号量sigNum
	if (!ReadFile(pipe, &sigNum, 1, &bytes, NULL))
	{
		/* Client died before sending */
		CloseHandle(pipe);
		return 0;
	}
	if (bytes != 1)
	{
		/* Received <bytes> bytes over signal pipe (should be 1) */
		CloseHandle(pipe);
		return 0;
	}
	WriteFile(pipe, &sigNum, 1, &bytes, NULL);	/* Don't care if it works or
												 * not.. */
	FlushFileBuffers(pipe);
	DisconnectNamedPipe(pipe);
	CloseHandle(pipe);

	// 设置信号量，并激活Event
	pg_queue_signal(sigNum);
	return 0;
}

/* Signal handling thread */
// 创建管道，等待连接，有连接后启动pg_signal_dispatch_thread线程处理
static DWORD WINAPI
pg_signal_thread(LPVOID param)
{
	char		pipename[128];
	HANDLE		pipe = pgwin32_initial_signal_pipe;

	snprintf(pipename, sizeof(pipename), "\\\\.\\pipe\\pgsignal_%lu", GetCurrentProcessId());

	for (;;)
	{
		BOOL		fConnected;
		HANDLE		hThread;

		// 始终保持管道存在
		if (pipe == INVALID_HANDLE_VALUE)
		{
		    // 创建命名管道
			pipe = CreateNamedPipe(pipename, PIPE_ACCESS_DUPLEX,
					   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
							   PIPE_UNLIMITED_INSTANCES, 16, 16, 1000, NULL);

			if (pipe == INVALID_HANDLE_VALUE)
			{
				write_stderr("could not create signal listener pipe: error code %d; retrying\n", (int) GetLastError());
				SleepEx(500, FALSE);
				continue;
			}
		}

		// 等待客户端连接命名管道，阻塞
		fConnected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		if (fConnected)
		{
		    // pg_signal_dispatch_thread 从管道接收客户端发来的信号，设置信号量，并激活事件处理
			hThread = CreateThread(NULL, 0,
						  (LPTHREAD_START_ROUTINE) pg_signal_dispatch_thread,
								   (LPVOID) pipe, 0, NULL);
			if (hThread == INVALID_HANDLE_VALUE)
				write_stderr("could not create signal dispatch thread: error code %d\n",
							 (int) GetLastError());
			else
				CloseHandle(hThread);
		}
		else
			/* Connection failed. Cleanup and try again */
			CloseHandle(pipe);

		/* Set up so we create a new pipe on next loop */
		pipe = INVALID_HANDLE_VALUE;
	}
	return 0;
}


/* Console control handler will execute on a thread created
   by the OS at the time of invocation */
static BOOL WINAPI
pg_console_handler(DWORD dwCtrlType)
{
	if (dwCtrlType == CTRL_C_EVENT ||
		dwCtrlType == CTRL_BREAK_EVENT ||
		dwCtrlType == CTRL_CLOSE_EVENT ||
		dwCtrlType == CTRL_SHUTDOWN_EVENT)
	{
	    // 设置信号量pg_signal_queue，并激活事件 pgwin32_signal_event
		pg_queue_signal(SIGINT);
		return TRUE;
	}
	return FALSE;
}
