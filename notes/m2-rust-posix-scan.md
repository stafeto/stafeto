# Rust directory selection and C locale ordering

The GPL-3.0-or-later Rust C ABI exports scandir and alphasort, with allocation
supplied by the process heap. The same milestone adds qsort, qsort_r,
strcmp, strcoll, strxfrm and initial setlocale declarations to the sysroot.
All new Rust modules, packages and C headers carry their GPL identifiers.

## Selection and ownership

scandir opens its own descriptor-backed directory stream and calls the
selection function once per entry. A null selection function accepts all
entries. Each accepted entry is copied into a separately allocated dirent;
the pointer array grows with checked reallocarray calls. Its capacity may
exceed the number returned. The caller frees each entry and then the array.
An empty selection returns zero and a freeable zero-size array allocation.
The returned count is limited to the positive int range; overflow fails
with EOVERFLOW before another entry is installed.

Success transfers ownership only after reading and closing the directory.
Failure preserves the caller's output pointer, frees accepted entries and
the array, and attempts to close the internal stream. Cleanup preserves the
original error. A null output pointer reports EFAULT before opening a file.
The internal read result distinguishes EOF from an error without changing
errno, so a selection callback may set errno without fabricating a read error.
Success restores the original errno, including after comparator callbacks.

Callbacks execute outside the file-context borrow and may use other directory
streams or allocation. They must not invalidate entries supplied to them.
A null comparator leaves entries in scan order as an implementation extension.
Successful results are independent of stream buffers and remain live after
subsequent directory reads until explicitly freed.

## Sorting

posix-order supplies a nonrecursive heap sort over index callbacks. It uses
no allocator and needs constant auxiliary storage. qsort swaps bytes of
disjoint elements, preserving arbitrary record payloads and alignment.
Comparison arguments always point into the actual caller array. Equal
elements have unspecified relative order. qsort_r uses the POSIX comparator
signature with context as the last parameter; recursive sorts use their
own contexts and do not require global comparator storage.
scandir sorts its pointer array through qsort_r with a typed adapter.

## Locale boundary

setlocale currently accepts C and POSIX for every standard category and
reports C as their canonical name. A query leaves state unchanged. Other
locale names return NULL without changing the selected locale or errno.
An empty name checks nonempty LC_ALL, the category variable, LANG and then
the C default. LC_ALL requests validate all categories before succeeding.
Environment strings are borrowed from environ; callers must synchronize
environment mutation. Startup still provides an empty environment until
program environment inheritance is implemented.

strcmp and C/POSIX strcoll compare unsigned bytes, including bytes above
0x7f and proper prefixes. strxfrm's key is the original byte sequence;
it returns the full length excluding NUL, permits a null destination for
zero capacity, and writes a terminator only when the full key fits.
alphasort delegates to strcoll on d_name. This establishes C/POSIX ordering;
locale databases, locale_t, wide-character and other locale APIs remain work.

## Validation

Three host tests verify byte ordering, compare sorting with a reference for
520 input shapes, and preserve record identity under contextual reverse
ordering. Reversing the heap child choice deliberately fails the reference
test. Omitting entry cleanup deliberately ends the C probe with status 137
when freed space cannot be reused after allocation failure.
The C probe checks locale queries and rejections, environment
precedence, unsigned comparison, transformed lengths and bounds, qsort and
reentrant qsort_r. Directory checks cover owned copies, callback reentry,
filter and reverse order, empty selection, missing paths and repeated reuse.
Memory pressure begins after the first accepted entry; the second allocation
fails with ENOMEM, leaves the output untouched, and cleanup makes space for
a new allocation before the pressure allocations are released.

The guest probes run through Cargo and standalone Clang/LLD; native errno
and heap-sharing checks run afterwards. The full cargo xtask ci includes
the host ordering tests and both C guest programs. BusyBox retains the MIT
bridge while the separate Rust POSIX service remains pending.

References: [scandir and alphasort](https://pubs.opengroup.org/onlinepubs/9799919799/functions/alphasort.html),
[qsort and qsort_r](https://pubs.opengroup.org/onlinepubs/9799919799/functions/qsort.html),
[locale environment precedence](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap08.html).
