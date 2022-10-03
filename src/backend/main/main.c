/*-------------------------------------------------------------------------
 *
 * main.c
 *	  Stub main() routine for the postgres executable.
 *
 * This does some essential startup tasks for any incarnation of postgres
 * (postmaster, standalone backend, or standalone bootstrap mode) and then
 * dispatches to the proper FooMain() routine for the incarnation.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/main/main.c,v 1.112 2009/01/01 17:23:43 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <pwd.h>
#include <unistd.h>

#if defined(__alpha) && defined(__osf__)		/* no __alpha__ ? */
#include <sys/sysinfo.h>
#include "machine/hal_sysinfo.h"
#define ASSEMBLER
#include <sys/proc.h>
#undef ASSEMBLER
#endif

#if defined(__NetBSD__)
#include <sys/param.h>
#endif

#include "bootstrap/bootstrap.h"
#include "postmaster/postmaster.h"
#include "resourcemanager/resourcemanager.h"
#include "tcop/tcopprot.h"
#include "utils/help_config.h"
#include "utils/pg_locale.h"
#include "utils/ps_status.h"
#ifdef WIN32
#include "libpq/pqsignal.h"
#endif

#include "catalog/catversion.h"

const char *progname;


static void startup_hacks(const char *progname);
static void help(const char *progname);
static void check_root(const char *progname);
static char *get_current_username(const char *progname);



int
main(int argc, char *argv[])
{
	progname = get_progname(argv[0]);

	/*
	 * Platform-specific startup hacks
	 *
	 * 对各种操作系统和cpu架构做相应的检查和处理
	 */
	startup_hacks(progname);

	/*
	 * Remember the physical location of the initially given argv[] array for
	 * possible use by ps display.	On some platforms, the argv[] storage must
	 * be overwritten in order to set the process title for ps. In such cases
	 * save_ps_display_args makes and returns a new copy of the argv[] array.
	 *
	 * save_ps_display_args may also move the environment strings to make
	 * extra room. Therefore this should be done as early as possible during
	 * startup, to avoid entanglements with code that might save a getenv()
	 * result pointer.
	 *
	 * 保存最初的argv[]的物理位置，以供ps显示使用。
	 * 在某些平台上，必须覆盖写argv[]存储才能设置ps的进程标题。
	 * 在这种情况下，save_ps_display_args会生成并返回argv[]的新副本。
	 * save_ps_display_args还可以移动环境字符串以腾出额外空间。
	 * 因此，这应该在启动期间尽早完成，以避免与可能保存getenv（）结果指针的代码纠缠。
	 *
	 * new_argv = (char **) malloc
	 * new_orgv <- argv
	 * return new_argv
	 */
	argv = save_ps_display_args(argc, argv);

	/*
	 * Set up locale information from environment.	Note that LC_CTYPE and
	 * LC_COLLATE will be overridden later from pg_control if we are in an
	 * already-initialized database.  We set them here so that they will be
	 * available to fill pg_control during initdb.	LC_MESSAGES will get set
	 * later during GUC option processing, but we set it here to allow startup
	 * error messages to be localized.
	 *
	 * 在环境中设置“区域设置信息”。
	 * 请注意，如果我们在一个已经初始化的数据库中，LC_CTYPE和LC_COLLATE稍后将从pg_control中重写。
	 * 我们在这里设置它们，以便它们可以在initdb期间填充pg_control。
	 * LC_MESSAGES稍后将在GUC选项处理期间设置，但我们在此处设置它以允许本地化启动错误消息。
	 */
	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("postgres"));

#ifdef WIN32

	/*
	 * Windows uses codepages rather than the environment, so we work around
	 * that by querying the environment explicitly first for LC_COLLATE and
	 * LC_CTYPE. We have to do this because initdb passes those values in the
	 * environment. If there is nothing there we fall back on the codepage.
	 */
	// 数据库参数说明
    // pg_perm_setlocale 地域设置，并putenv到环境变量
	{
		char	   *env_locale;

        //LC_COLLATE 字符串排序的顺序
		if ((env_locale = getenv("LC_COLLATE")) != NULL)
			pg_perm_setlocale(LC_COLLATE, env_locale);
		else
			pg_perm_setlocale(LC_COLLATE, "");

        //LC_CTYPE 字符分类
		if ((env_locale = getenv("LC_CTYPE")) != NULL)
			pg_perm_setlocale(LC_CTYPE, env_locale);
		else
			pg_perm_setlocale(LC_CTYPE, "");
	}
#else
	pg_perm_setlocale(LC_COLLATE, "");
	pg_perm_setlocale(LC_CTYPE, "");
#endif

#ifdef LC_MESSAGES
    //LC_MESSAGES 消息的语言
	pg_perm_setlocale(LC_MESSAGES, "");
#endif

	/*
	 * We keep these set to "C" always, except transiently in pg_locale.c; see
	 * that file for explanations.
	 */
    //LC_MONETARY 货币使用的格式
	pg_perm_setlocale(LC_MONETARY, "C");
    //LC_NUMERIC 数字使用的格式
	pg_perm_setlocale(LC_NUMERIC, "C");
    //LC_TIME 时间日期使用的格式
	pg_perm_setlocale(LC_TIME, "C");

	/*
	 * Now that we have absorbed as much as we wish to from the locale
	 * environment, remove any LC_ALL setting, so that the environment
	 * variables installed by pg_perm_setlocale have force.
	 */
	unsetenv("LC_ALL");

	/*
	 * Catch standard options before doing much else
	 */
	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			help(progname);
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
		    // 自动配置
		    // https://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf-2.71/autoconf.html#Introduction
		    // /* src/include/pg_config.h.in.  Generated from configure.in by autoheader.  */
			puts("postgres (HAWQ) " PG_VERSION);
			exit(0);
		}
		if (strcmp(argv[1], "--gp-version") == 0)
		{
			puts("postgres (HAWQ) " GP_VERSION);
			exit(0);
		}
		if (strcmp(argv[1], "--hawq-version") == 0)
		{
			puts("postgres (HAWQ) " HQ_VERSION);
			exit(0);
		}
		if (strcmp(argv[1], "--catalog-version") == 0 )
		{
		    // C:\Workspace\hawq\src\include\catalog\catversion.h
		    // #define CATALOG_VERSION_NO      201507221
			printf(_("Catalog version number:               %u\n"),
				   CATALOG_VERSION_NO);
			exit(0);
		}
	}

	/*
	 * Make sure we are not running as root.
	 */
	check_root(progname);

	/*
	 * Dispatch to one of various subprograms depending on first argument.
	 */
// GCC编译器中使用-D参数在编译阶段定义
#ifdef EXEC_BACKEND
	if (argc > 1 && strncmp(argv[1], "--fork", 6) == 0)
	    // C:\Workspace\hawq\src\backend\postmaster\postmaster.c
		exit(SubPostmasterMain(argc, argv));
#endif

#ifdef WIN32

	/*
	 * Start our win32 signal implementation
	 *
	 * SubPostmasterMain() will do this for itself, but the remaining modes
	 * need it here
	 */
	// win32系统的signal/Event处理机制初始化
	pgwin32_signal_initialize();
#endif

	if (argc > 1 && strcmp(argv[1], "--boot") == 0)
		AuxiliaryProcessMain(argc, argv);		/* does not return */

	if (argc > 1 && strcmp(argv[1], "--describe-config") == 0)
		exit(GucInfoMain());

	if (argc > 1 && strcmp(argv[1], "--single") == 0)
		exit(PostgresMain(argc, argv, get_current_username(progname)));

	if (strcmp(progname, "postmaster") == 0)
	{
		/* Called as "postmaster" */
		exit(PostmasterMain(argc, argv));
	}
    
    /* for gpsyncmaster */
    if (strcmp(get_progname(argv[0]), "gpsyncmaster") == 0)
    {
        /* Called as "postmaster" */
        exit(gpsyncMain(argc, argv));
    }

    /* for resource manager process, for singla-process mode testing of resource
	   manager, this is invoked. */
    if (strcmp(progname, "resmanager") == 0)
    {
        exit(ResManagerMain(argc,argv));
    }

	exit(PostmasterMain(argc, argv));
}



/*
 * Place platform-specific startup hacks here.	This is the right
 * place to put code that must be executed early in launch of either a
 * postmaster, a standalone backend, or a standalone bootstrap run.
 * Note that this code will NOT be executed when a backend or
 * sub-bootstrap run is forked by the server.
 *
 * XXX The need for code here is proof that the platform in question
 * is too brain-dead to provide a standard C execution environment
 * without help.  Avoid adding more here, if you can.
 *
 * 在此处放置平台特定的启动黑客。
 * 这是放置代码的正确位置，必须在运行下列情况的早期执行，启动postmaster、独立后端或独立引导。
 * 请注意，当服务器分叉后端或子引导运行时，不会执行此代码。
 * XXX这里对代码的需求证明，所讨论的平台太死板，在没有帮助的情况下无法提供标准的C执行环境。
 * 如果可以，请避免在此处添加更多内容。
 */
static void
startup_hacks(const char *progname)
{
    // NOFIXADE在port/osf.h和ultrix4.h中有定义
    // 各式各样的Unix衍生产品。如AIX、Solaris、HP-UX、IRIX、OSF、Ultrix等等。
    // ULTRIX是Digital Equipment Corporation于1984年为VAX 最初发布的Unix 操作系统的本机版本的名称。
    // 1991年底，与System V针锋相对的开放软件基金会(Open Software Foundation)推出了OSF/1。
    // Alpha处理器最早由DEC公司设计制造，目前国内采用此架构的是申微超算处理器
    // 目前市场上的CPU分类主要分有两大阵营，一个是intel、AMD为首的复杂指令集CPU，另一个是以IBM、ARM为首的精简指令集CPU。
    // 不同品牌的CPU，其产品的架构也不相同。
    // Intel、AMD的CPU是X86架构，IBM公司的CPU是PowerPC架构，ARM公司的CPU是ARM架构，国内的飞腾CPU也是ARM架构。
    // 此外还有MPIS架构、SPARC架构、Alpha架构


#if defined(__alpha)			/* no __alpha__ ? */
#ifdef NOFIXADE
	int			buffer[] = {SSIN_UACPROC, UAC_SIGBUS | UAC_NOPRINT};
#endif
#endif   /* __alpha */
	/*
	 * On some platforms, unaligned memory accesses result in a kernel trap;
	 * the default kernel behavior is to emulate the memory access, but this
	 * results in a significant performance penalty. We ought to fix PG not to
	 * make such unaligned memory accesses, so this code disables the kernel
	 * emulation: unaligned accesses will result in SIGBUS instead.
	 *
	 * 在某些平台上，未对齐的内存访问会导致内核陷阱；默认的内核行为是模拟内存访问，但这会导致严重的性能损失。
	 * 我们应该修复PG，使其不进行这种未对齐的内存访问，因此此代码禁用内核仿真：未对齐的访问将导致SIGBUS。
	 */
#ifdef NOFIXADE

#if defined(ultrix4)
	// 系统调用，地址对齐
	// MIPS 下使用访存指令读取或写入数据单元时，目标地址必须是所访问之数据单元字节数的整数倍，这个叫做地址对齐。
	// https://blog.csdn.net/zmc1216/article/details/44782183
	// https://www.jianshu.com/p/552facb28e58
	syscall(SYS_sysmips, MIPS_FIXADE, 0, NULL, NULL, NULL);
#endif

#if defined(__alpha)			/* no __alpha__ ? */
    //http://www2.phys.canterbury.ac.nz/dept/docs/manuals/unix/DEC_5.0a_Docs/HTML/MAN/MAN2/0124____.HTM
    //setsysinfo - 设置系统信息
    //SSI_NVPAIRS
    //  此操作使用成对的值或其命名的等价物来
    //  修改系统行为。缓冲区变量是成对的数组
    //  值（或其命名的等价物）。
    //SSIN_UACPROC在proc结构
    //  中设置的值。这个值是成对的
    //  带有 UAC 标志 UAC_NOPRINT、UAC_NOFIX 和 UAC_SIGBUS，在
    //  任何组合，包括OR。因此，它切换
    //  打印“未对齐访问修复”消息，修复 UAC
    //  故障，并向线程传递 SIGBUS 信号。
    //UAC_NOPRINT禁止将未对齐的错误消息打印到用户。
    //UAC_SIGBUS导致将 SIGBUS 信号传递给线程。
	if (setsysinfo(SSI_NVPAIRS, buffer, 1, (caddr_t) NULL,
				   (unsigned long) NULL) < 0)
		write_stderr("%s: setsysinfo failed: %s\n",
					 progname, strerror(errno));
#endif
#endif   /* NOFIXADE */


#ifdef WIN32
	{
		WSADATA		wsaData;
		int			err;

		/* Make output streams unbuffered by default */
		setvbuf(stdout, NULL, _IONBF, 0);
		setvbuf(stderr, NULL, _IONBF, 0);

		/* Prepare Winsock
		 * WSAStartup必须是应用程序或DLL调用的第一个Windows Sockets函数。
		 * 它允许应用程序或DLL指明Windows Sockets API的版本号及获得特定Windows Sockets实现的细节。
		 * 应用程序或DLL只能在一次成功的WSAStartup()调用之后才能调用进一步的Windows Sockets API函数。
		 *
		 * 此处为2.2版
		 *
		 * */
		err = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (err != 0)
		{
			write_stderr("%s: WSAStartup failed: %d\n",
						 progname, err);
			exit(1);
		}

		/* In case of general protection fault, don't show GUI popup box */
		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	}
#endif   /* WIN32 */
}


/*
 * Help display should match the options accepted by PostmasterMain()
 * and PostgresMain().
 */
static void
help(const char *progname)
{
	printf(_("%s is the PostgreSQL server.\n\n"), progname);
	printf(_("Usage:\n  %s [OPTION]...\n\n"), progname);
	printf(_("Options:\n"));
#ifdef USE_ASSERT_CHECKING
	printf(_("  -A 1|0          enable/disable run-time assert checking\n"));
#endif
	printf(_("  -B NBUFFERS     number of shared buffers\n"));
	printf(_("  -c NAME=VALUE   set run-time parameter\n"));
	printf(_("  -d 1-5          debugging level\n"));
	printf(_("  -D DATADIR      database directory\n"));
	printf(_("  -e              use European date input format (DMY)\n"));
	printf(_("  -F              turn fsync off\n"));
	printf(_("  -h HOSTNAME     host name or IP address to listen on\n"));
	printf(_("  -i              enable TCP/IP connections\n"));
	printf(_("  -k DIRECTORY    Unix-domain socket location\n"));
#ifdef USE_SSL
	printf(_("  -l              enable SSL connections\n"));
#endif
	printf(_("  -N MAX-CONNECT  maximum number of allowed connections\n"));
	printf(_("  -o OPTIONS      pass \"OPTIONS\" to each server process (obsolete)\n"));
	printf(_("  -p PORT         port number to listen on\n"));
	printf(_("  -s              show statistics after each query\n"));
	printf(_("  -S WORK-MEM     set amount of memory for sorts (in kB)\n"));
	printf(_("  --NAME=VALUE    set run-time parameter\n"));
	printf(_("  --describe-config  describe configuration parameters, then exit\n"));
	printf(_("  --help          show this help, then exit\n"));
	printf(_("  --version       output version information, then exit\n"));
	printf(_("  --gp-version    output Greenplum version information, then exit\n"));
	printf(_("  --hawq-version    output Greenplum version information, then exit\n"));
	printf(_("  --catalog-version output the catalog version, then exit\n"));

	printf(_("\nDeveloper options:\n"));
	printf(_("  -f s|i|n|m|h    forbid use of some plan types\n"));
	printf(_("  -n              do not reinitialize shared memory after abnormal exit\n"));
	printf(_("  -O              allow system table structure changes\n"));
	printf(_("  -P              disable system indexes\n"));
	printf(_("  -t pa|pl|ex     show timings after each query\n"));
	printf(_("  -T              send SIGSTOP to all backend servers if one dies\n"));
	printf(_("  -W NUM          wait NUM seconds to allow attach from a debugger\n"));

	printf(_("\nOptions for maintenance mode:\n"));
	printf(_("  -m              start the system in maintenance mode\n"));

	printf(_("\nOptions for upgrade mode:\n"));
	printf(_("  -U              start the system in upgrade mode\n"));

	printf(_("\nOptions for single-user mode:\n"));
	printf(_("  --single        selects single-user mode (must be first argument)\n"));
	printf(_("  DBNAME          database name (defaults to user name)\n"));
	printf(_("  -d 0-5          override debugging level\n"));
	printf(_("  -E              echo statement before execution\n"));
	printf(_("  -j              do not use newline as interactive query delimiter\n"));
	printf(_("  -r FILENAME     send stdout and stderr to given file\n"));

	printf(_("\nOptions for bootstrapping mode:\n"));
	printf(_("  --boot          selects bootstrapping mode (must be first argument)\n"));
	printf(_("  DBNAME          database name (mandatory argument in bootstrapping mode)\n"));
	printf(_("  -r FILENAME     send stdout and stderr to given file\n"));
	printf(_("  -x NUM          internal use\n"));

	printf(_("\nGPDB-specific options:\n"));
	printf(_("  -b <dbid>       startup with a particular db-id\n"));
	printf(_("  -C <contentid>  startup with a particular content-id\n"));
	printf(_("  -z <seg-count>  startup with a given number of content-ids\n"));

	printf(_("\nPlease read the documentation for the complete list of run-time\n"
	 "configuration settings and how to set them on the command line or in\n"
			 "the configuration file.\n\n"
			 "Report bugs to <pgsql-bugs@postgresql.org>.\n"));
}



static void
check_root(const char *progname)
{
#ifndef WIN32
	if (geteuid() == 0)
	{
		write_stderr("\"root\" execution of the PostgreSQL server is not permitted.\n"
					 "The server must be started under an unprivileged user ID to prevent\n"
		  "possible system security compromise.  See the documentation for\n"
				  "more information on how to properly start the server.\n");
		exit(1);
	}

	/*
	 * Also make sure that real and effective uids are the same. Executing as
	 * a setuid program from a root shell is a security hole, since on many
	 * platforms a nefarious subroutine could setuid back to root if real uid
	 * is root.  (Since nobody actually uses postgres as a setuid program,
	 * trying to actively fix this situation seems more trouble than it's
	 * worth; we'll just expend the effort to check for it.)
	 *
	 * 还要确保真实的和有效的uid是相同的。
	 * 从根shell作为setuid程序执行是一个安全漏洞，因为在许多平台上，如果真正的uid是root，邪恶的子例程可能会将uid设置回root。
	 * （因为实际上没有人使用postgres作为setuid程序，所以尝试主动修复这种情况似乎比实际情况要麻烦得多；我们只需花费精力进行检查。）
	 *
	 * geteuid()：返回有效用户的ID
	 * getuid()：返回实际用户的ID。
	 */
	if (getuid() != geteuid())
	{
		write_stderr("%s: real and effective user IDs must match\n",
					 progname);
		exit(1);
	}
#else							/* WIN32 */
#if 0
	if (pgwin32_is_admin())
	{
		write_stderr("Execution of PostgreSQL by a user with administrative permissions is not\n"
					 "permitted.\n"
					 "The server must be started under an unprivileged user ID to prevent\n"
		 "possible system security compromises.  See the documentation for\n"
				  "more information on how to properly start the server.\n");
		exit(1);
	}
#endif
#endif   /* WIN32 */
}



static char *
get_current_username(const char *progname)
{
#ifndef WIN32
	struct passwd *pw;

	pw = getpwuid(geteuid());
	if (pw == NULL)
	{
		write_stderr("%s: invalid effective UID: %d\n",
					 progname, (int) geteuid());
		exit(1);
	}
	/* Allocate new memory because later getpwuid() calls can overwrite it. */
	return strdup(pw->pw_name);
#else
	long		namesize = 256 /* UNLEN */ + 1;
	char	   *name;

	name = malloc(namesize);
	if (!GetUserName(name, &namesize))
	{
		write_stderr("%s: could not determine user name (GetUserName failed)\n",
					 progname);
		exit(1);
	}

	return name;
#endif
}
