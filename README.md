# Arena Allocator

[Arena Allocator](https://en.wikipedia.org/wiki/Region-based_memory_management) implementation in pure C as an [stb-style single-file library](https://github.com/nothings/stb).

*I just caught myself implementing this over and over again in my projects, so I decided to turn it into a copy-pastable library similar to [sv](http://github.com/tsoding/sv)*

## Quick Start

> The truly reusable code is the one that you can simply copy-paste.

The library itself does not require any special building. You can simple copy-paste [./arena.h](./arena.h) to your project and `#include` it.

```c
#define ARENA_IMPLEMENTATION
#include "arena.h"

int main(void)
{
    Arena arena = {0};

    // Allocate stuff in arena
    arena_alloc(&arena, 64);
    arena_alloc(&arena, 128);
    arena_alloc(&arena, 256);
    arena_alloc(&arena, 512);
    void *p;

    {
        ArenaSnapshot snapshot = arena_snapshot(&arena);

        // Allocate stuff in temporary arena
        p = arena_alloc(&arena, 64);
        arena_alloc(&arena, 128);
        arena_alloc(&arena, 256);
        arena_alloc(&arena, 512);

        arena_rewind(&arena, snapshot);
    }

    assert(p == arena_alloc(&arena, 64));
    // Deallocate everything at once
    arena_deinit(&arena);
    return 0;
}
```

## Incompatibilities with upstream

Some things like `arena_memdup()`, `arena_strdup()` and `arena_da_append()`
have been moved to [dynamic_array](https://github.com/ListeriaM/dynamic_array)
and made independent of the underlying allocator implementation.
