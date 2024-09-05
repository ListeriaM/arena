// Copyright 2022 Alexey Kutepov <reximkut@gmail.com>
// Copyright 2024 Listeria monocytogenes <listeria@disroot.org>

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef ARENA_H_
#define ARENA_H_

#include <stddef.h>

/* compile with -funreachable-traps (or -fsanitize=unreachable
 * -fsanitize-trap=unreachable) to keep assertions in release builds */
#ifndef ARENA_ASSERT
# if defined(assert)
#  define ARENA_ASSERT assert
# elif defined(unreachable)
#  define ARENA_ASSERT(condition) ((condition) ? (void)0 : unreachable())
# elif defined(__GNUC__)
#  define ARENA_ASSERT(condition) ((condition) ? (void)0 : __builtin_unreachable())
# elif defined(_MSC_VER)
#  define ARENA_ASSERT __assume
# else
#  include <assert.h>
#  define ARENA_ASSERT assert
# endif
#endif

#ifndef ARENA_DEF
# define ARENA_DEF
#endif

#define ARENA_BACKEND_LIBC_MALLOC 0
#define ARENA_BACKEND_LINUX_MMAP 1
#define ARENA_BACKEND_WIN32_VIRTUALALLOC 2
#define ARENA_BACKEND_WASM_HEAPBASE 3

#ifndef ARENA_BACKEND
# define ARENA_BACKEND ARENA_BACKEND_LIBC_MALLOC
#endif

typedef struct ArenaRegion ArenaRegion;

typedef struct ArenaSnapshot {
    ArenaRegion *region;
    size_t count;
} ArenaSnapshot;

typedef struct Arena {
    ArenaRegion *begin, *end;
    size_t count;
} Arena;

ARENA_DEF void arena_reset(Arena *a);
ARENA_DEF void arena_deinit(Arena *a);

// snapshot/rewind capability for the arena.
ARENA_DEF ArenaSnapshot arena_snapshot(Arena *a);
ARENA_DEF void arena_rewind(Arena *a, ArenaSnapshot s);

ARENA_DEF void *arena_alloc(Arena *a, size_t size_bytes);
ARENA_DEF void *arena_realloc(Arena *a, void *oldptr, size_t oldsz, size_t newsz);
ARENA_DEF void  arena_free(Arena *a, void *ptr, size_t size_bytes);

#endif // ARENA_H_

#ifdef ARENA_IMPLEMENTATION
#undef ARENA_IMPLEMENTATION

typedef struct arena__unknown arena__unknown;

// Using max_align_t here would work if sizeof(max_align_t) were guaranteed to
// be the same as alignof(max_align_t).
// Since that's not the case we use our own typedef'ed union.
typedef union {
    long int li;
    long double ld;
    void *vp;
    arena__unknown (*fp)(arena__unknown);
    struct { long int li; } sli;
    struct { long double ld; } sld;
    struct { void *vp; } svp;
    struct { arena__unknown (*fp)(arena__unknown); } sfp;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L || \
    defined(__cplusplus) && __cplusplus >= 201103L
    long long int lli;
    struct { long long int lli; } slli;
#endif
#if defined (__cplusplus)
    // See http://erdani.org/publications/cuj-06-2002.php.html
    arena__unknown* arena__unknown::*mp;
    arena__unknown (arena__unknown::*mf)(arena__unknown);
    struct { arena__unknown* arena__unknown::*mp; } smp;
    struct { arena__unknown (arena__unknown::*mf)(arena__unknown); } smf;
#endif
} arena__max_align;

struct ArenaRegion {
    ArenaRegion *next;
    size_t capacity;
    arena__max_align data[];
};

#define REGION_DEFAULT_CAPACITY (8*1024)

static ArenaRegion *arena__new_region(size_t capacity);
static void arena__free_region(ArenaRegion *r);

#if ARENA_BACKEND == ARENA_BACKEND_LIBC_MALLOC
#include <stdlib.h>

// TODO: instead of accepting specific capacity arena__new_region() should accept the size of the object we want to fit into the region
// It should be up to arena__new_region() to decide the actual capacity to allocate
static ArenaRegion *arena__new_region(size_t capacity)
{
    size_t size_bytes = sizeof(ArenaRegion) + sizeof(arena__max_align) * capacity;
    // TODO: it would be nice if we could guarantee that the regions are allocated by ARENA_BACKEND_LIBC_MALLOC are page aligned
    ArenaRegion *r = (ArenaRegion*)malloc(size_bytes);
    ARENA_ASSERT(r);
    r->next = NULL;
    r->capacity = capacity;
    return r;
}

static void arena__free_region(ArenaRegion *r)
{
    free(r);
}

#elif ARENA_BACKEND == ARENA_BACKEND_LINUX_MMAP
#include <unistd.h>
#include <sys/mman.h>

static ArenaRegion *arena__new_region(size_t capacity)
{
    size_t size_bytes = sizeof(ArenaRegion) + sizeof(arena__max_align) * capacity;
    ArenaRegion *r = (ArenaRegion*)mmap(NULL, size_bytes, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    ARENA_ASSERT(r != MAP_FAILED);
    r->next = NULL;
    r->capacity = capacity;
    return r;
}

static void arena__free_region(ArenaRegion *r)
{
    size_t size_bytes = sizeof(ArenaRegion) + sizeof(arena__max_align) * r->capacity;
    int ret = munmap(r, size_bytes);
    ARENA_ASSERT(ret == 0);
}

#elif ARENA_BACKEND == ARENA_BACKEND_WIN32_VIRTUALALLOC

#if !defined(_WIN32)
#  error "Current platform is not Windows"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define INV_HANDLE(x)       (((x) == NULL) || ((x) == INVALID_HANDLE_VALUE))

static ArenaRegion *arena__new_region(size_t capacity)
{
    SIZE_T size_bytes = sizeof(ArenaRegion) + sizeof(arena__max_align) * capacity;
    ArenaRegion *r = (ArenaRegion*)VirtualAllocEx(
        GetCurrentProcess(),      /* Allocate in current process address space */
        NULL,                     /* Unknown position */
        size_bytes,               /* Bytes to allocate */
        MEM_COMMIT | MEM_RESERVE, /* Reserve and commit allocated page */
        PAGE_READWRITE            /* Permissions ( Read/Write )*/
    );
    if (INV_HANDLE(r))
        ARENA_ASSERT(0 && "VirtualAllocEx() failed.");

    r->next = NULL;
    r->capacity = capacity;
    return r;
}

static void arena__free_region(ArenaRegion *r)
{
    if (INV_HANDLE(r))
        return;

    BOOL free_result = VirtualFreeEx(
        GetCurrentProcess(),        /* Deallocate from current process address space */
        (LPVOID)r,                  /* Address to deallocate */
        0,                          /* Bytes to deallocate ( Unknown, deallocate entire page ) */
        MEM_RELEASE                 /* Release the page ( And implicitly decommit it ) */
    );

    if (FALSE == free_result)
        ARENA_ASSERT(0 && "VirtualFreeEx() failed.");
}

#elif ARENA_BACKEND == ARENA_BACKEND_WASM_HEAPBASE
#  error "TODO: WASM __heap_base backend is not implemented yet"
#else
#  error "Unknown Arena backend"
#endif

// TODO: add debug statistic collection mode for arena
// Should collect things like:
// - How many times arena__new_region was called
// - How many times existing region was skipped
// - How many times allocation exceeded REGION_DEFAULT_CAPACITY

ARENA_DEF void *arena_alloc(Arena *a, size_t size_bytes)
{
    size_t size = (size_bytes + sizeof(arena__max_align) - 1)/sizeof(arena__max_align);

    if (a->end == NULL) {
        ARENA_ASSERT(a->begin == NULL);
        size_t capacity = REGION_DEFAULT_CAPACITY;
        if (capacity < size) capacity = size;
        a->end = arena__new_region(capacity);
        a->begin = a->end;
        a->count = 0;
    }


    ArenaRegion *old_end = a->end;
    ArenaRegion **end_p = NULL;
    while (a->count + size > a->end->capacity && a->end->next != NULL) {
        end_p = &a->end->next;
        a->end = *end_p;
        a->count = 0;
    }

    if (end_p != NULL) {
        *end_p = a->end->next;
        a->end->next = old_end->next;
        old_end->next = a->end;
    }

    if (a->count + size > a->end->capacity) {
        size_t capacity = REGION_DEFAULT_CAPACITY;
        if (capacity < size) capacity = size;
        ArenaRegion *r = arena__new_region(capacity);
        r->next = old_end->next;
        old_end->next = r;
        a->end = r;
        a->count = 0;
    }

    void *result = &a->end->data[a->count];
    a->count += size;
    return result;
}

ARENA_DEF void *arena_realloc(Arena *a, void *oldptr, size_t oldsz_bytes, size_t newsz_bytes)
{
    size_t oldsz = (oldsz_bytes + sizeof(arena__max_align) - 1)/sizeof(arena__max_align);
    size_t newsz = (newsz_bytes + sizeof(arena__max_align) - 1)/sizeof(arena__max_align);

    if (oldptr == NULL)
        return arena_alloc(a, newsz_bytes);

    if ((arena__max_align *)oldptr + oldsz == &a->end->data[a->count]
            && a->count - oldsz + newsz <= a->end->capacity) {
        a->count -= oldsz;
        a->count += newsz;
    } else if (newsz > oldsz) {
        void *newptr = arena_alloc(a, newsz_bytes);
        for (size_t i = 0; i < oldsz; i++)
            ((arena__max_align *)newptr)[i] = ((arena__max_align *)oldptr)[i];
        return newptr;
    }
    return oldptr;
}

ARENA_DEF void arena_free(Arena *a, void *ptr, size_t size_bytes)
{
    size_t sz = (size_bytes + sizeof(arena__max_align) - 1)/sizeof(arena__max_align);

    if (ptr != NULL && (arena__max_align *)ptr + sz == &a->end->data[a->count])
        a->count -= sz;
}

ARENA_DEF ArenaSnapshot arena_snapshot(Arena *a)
{
    ArenaSnapshot s;
    s.region = a->end;
    s.count = a->count;
    return s;
}

ARENA_DEF void arena_rewind(Arena *a, ArenaSnapshot s)
{
    a->end = (s.region != NULL) ? s.region : a->begin;
    a->count = s.count;
}

ARENA_DEF void arena_reset(Arena *a)
{
    a->end = a->begin;
    a->count = 0;
}


ARENA_DEF void arena_deinit(Arena *a)
{
    ArenaRegion *r = a->begin;
    while (r) {
        ArenaRegion *r0 = r;
        r = r->next;
        arena__free_region(r0);
    }
    a->begin = NULL;
    a->end = NULL;
    a->count = 0;
}

#endif // ARENA_IMPLEMENTATION
