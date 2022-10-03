/*-------------------------------------------------------------------------
 *
 * catversion.h
 *	  "Catalog version number" for PostgreSQL.
 *
 * The catalog version number is used to flag incompatible changes in
 * the PostgreSQL system catalogs.	Whenever anyone changes the format of
 * a system catalog relation, or adds, deletes, or modifies standard
 * catalog entries in such a way that an updated backend wouldn't work
 * with an old database (or vice versa), the catalog version number
 * should be changed.  The version number stored in pg_control by initdb
 * is checked against the version number compiled into the backend at
 * startup time, so that a backend can refuse to run in an incompatible
 * database.
 *
 * The point of this feature is to provide a finer grain of compatibility
 * checking than is possible from looking at the major version number
 * stored in PG_VERSION.  It shouldn't matter to end users, but during
 * development cycles we usually make quite a few incompatible changes
 * to the contents of the system catalogs, and we don't want to bump the
 * major version number for each one.  What we can do instead is bump
 * this internal version number.  This should save some grief for
 * developers who might otherwise waste time tracking down "bugs" that
 * are really just code-vs-database incompatibilities.
 *
 * The rule for developers is: if you commit a change that requires
 * an initdb, you should update the catalog version number (as well as
 * notifying the pghackers mailing list, which has been the informal
 * practice for a long time).
 *
 * The catalog version number is placed here since modifying files in
 * include/catalog is the most common kind of initdb-forcing change.
 * But it could be used to protect any kind of incompatible change in
 * database contents or layout, such as altering tuple headers.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/catalog/catversion.h,v 1.531 2009/06/11 14:49:09 momjian Exp $
 *
 * 目录版本号用于标记PostgreSQL系统目录中的不兼容更改。
 * 每当任何人更改系统目录关系的格式，或添加、删除或修改标准目录条目，使更新的后端无法处理旧数据库（反之亦然）时，应更改目录版本号。
 * initdb存储在pg_control中的版本号与启动时编译到后端的版本号进行检查，以便后端可以拒绝在不兼容的数据库中运行。
 *
 * 此功能的目的是提供比查看存储在PG_version中的主要版本号更精细的兼容性检查。
 * 对于最终用户来说，这不重要，但在开发周期中，我们通常会对系统目录的内容进行一些不兼容的更改，
 * 并且我们不希望每个目录都有主版本号。
 * 我们可以做的是修改这个内部版本号。
 * 这将为开发人员节省一些时间，否则他们可能会浪费时间来跟踪“bug”，这些bug实际上只是代码与数据库的不兼容。
 *
 * 开发人员的规则是：如果您提交了需要initdb的更改，则应更新目录版本号（以及通知pghackers邮件列表，
 * 这是长期以来的非正式做法）。
 *
 * 目录版本号放在这里，因为修改include/catalog中的文件是最常见的initdb强制更改。
 * 但它可以用于保护数据库内容或布局中的任何不兼容更改，例如更改元组头。
 *-------------------------------------------------------------------------
 */
#ifndef CATVERSION_H
#define CATVERSION_H

/*
 * We could use anything we wanted for version numbers, but I recommend
 * following the "YYYYMMDDN" style often used for DNS zone serial numbers.
 * YYYYMMDD are the date of the change, and N is the number of the change
 * on that day.  (Hopefully we'll never commit ten independent sets of
 * catalog changes on the same day...)
 *
 * N 同一天内的变更序号
 */

/*                              yyyymmddN */
#define CATALOG_VERSION_NO      201507221

#endif
