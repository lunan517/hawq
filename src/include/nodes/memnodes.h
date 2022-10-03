/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*-------------------------------------------------------------------------
 *
 * memnodes.h
 *	  POSTGRES memory context node definitions.
 *
 *
 * Portions Copyright (c) 2007-2008, Greenplum inc
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/nodes/memnodes.h,v 1.31 2006/03/05 15:58:56 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#ifndef MEMNODES_H
#define MEMNODES_H

#include "nodes/nodes.h"

/*
 * MemoryContext
 *		A logical context in which memory allocations occur.
 *      发生内存分配的逻辑上下文。
 * MemoryContext itself is an abstract type that can have multiple
 * implementations, though for now we have only AllocSetContext.
 * The function pointers in MemoryContextMethods define one specific
 * implementation of MemoryContext --- they are a virtual function table
 * in C++ terms.
 * MemoryContext本身是一种抽象类型，可以有多个实现，但目前我们只有AllocSetContext。
 * MemoryContextMethods中的函数指针定义了MemoryContext的一个特定实现——它们是C++术语中的一个虚拟函数表。
 *
 * Node types that are actual implementations of memory contexts must
 * begin with the same fields as MemoryContext.
 * 实际实现内存上下文的节点类型必须以与MemoryContext相同的字段开头。
 *
 * Note: for largely historical reasons, typedef MemoryContext is a pointer
 * to the context struct rather than the struct type itself.
 * 注意：由于历史原因，typedef MemoryContext是指向上下文结构的指针，而不是结构类型本身。
 */

typedef struct MemoryContextMethods
{
    /*在上下文中分配内存*/
	void	   *(*alloc) (MemoryContext context, Size size);
	/* call this free_p in case someone #define's free() */
    /* 释放pointer 内存到上下文中*/
	void		(*free_p) (MemoryContext context, void *pointer);
    /*在上下文中重新分配内存*/
	void	   *(*realloc) (MemoryContext context, void *pointer, Size size);
    /*上下文初始化*/
	void		(*init) (MemoryContext context);
    /*上下文复位*/
	void		(*reset) (MemoryContext context);
    /*删除上下文 */
	void		(*delete_context) (MemoryContext context);
    /*获取上下文块大小 */
	Size		(*get_chunk_space) (MemoryContext context, void *pointer);
    /*上下文是否为空*/
	bool		(*is_empty) (MemoryContext context);
    /*上下文信息统计*/
	void		(*stats) (MemoryContext context, uint64 *nBlocks, uint64 *nChunks, uint64 *currentAvailable, uint64 *allAllocated, uint64 *allFreed, uint64 *maxHeld);
	void		(*release_accounting)(MemoryContext context);
	void		(*update_generation)(MemoryContext context);
#ifdef MEMORY_CONTEXT_CHECKING
    /*上下文异常检查*/
	void		(*check) (MemoryContext context);
#endif
} MemoryContextMethods;


typedef struct MemoryContextData
{
	NodeTag		type;			/* identifies exact kind of context 上下文类别 */
	MemoryContextMethods methods;		/* virtual function table */
	MemoryContext parent;		/* NULL if no parent (toplevel context) 父上下文。顶级上下文为 NULL */
	MemoryContext firstchild;	/* head of linked list of children 子上下文的链表头 */
	MemoryContext nextchild;	/* next child of same parent 后向子上下文 */
	char	   *name;			/* context name (just for debugging) */
    /* CDB: Lifetime cumulative stats for this context and all descendants
     * 此上下文和所有后代的生存期累积统计信息*/
    uint64      allBytesAlloc;  /* bytes allocated from lower level mem mgr */
    uint64      allBytesFreed;  /* bytes returned to lower level mem mgr */
    Size        maxBytesHeld;   /* high-water mark for total bytes held */
    Size        localMinHeld;   /* low-water mark since last increase in hwm */
#ifdef CDB_PALLOC_CALLER_ID
    const char *callerFile;     /* __FILE__ of most recent caller */
    int         callerLine;     /* __LINE__ of most recent caller */
#endif
} MemoryContextData;

/* utils/palloc.h contains typedef struct MemoryContextData *MemoryContext */


/*
 * MemoryContextIsValid
 *		True iff memory context is valid.
 *
 * Add new context types to the set accepted by this macro.
 */
#define MemoryContextIsValid(context) \
	((context) != NULL && \
	 ( IsA((context), AllocSetContext) || \
       IsA((context), AsetDirectContext) || \
       IsA((context), MPoolContext) ))


#endif   /* MEMNODES_H */
