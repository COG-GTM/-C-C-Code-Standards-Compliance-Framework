---
trigger: always_on
---

# C/C++ Safety-Critical Code Standards

> Copy this file to `.windsurf/rules/c-safety-critical-rules.md` in your project.

## Overview

When reviewing C/C++ code, enforce these safety-critical rules and classify violations by severity. Report violations with their rule ID for traceability.

## Severity Levels

| Level | Icon | Action | Description |
|-------|------|--------|-------------|
| **Critical** | 🔴 | Block merge | Safety/security risk - crashes, vulnerabilities, data corruption |
| **Major** | 🟡 | Require review | Quality issue - potential bugs, edge case failures |
| **Minor** | 🟢 | Warn only | Style issue - readability, maintainability |

---

## Critical Rules (Block Merge) 🔴

### Rule 20: Check All Return Values

All return values from functions that can fail MUST be checked.

**Affected functions:** `malloc`, `calloc`, `realloc`, `fopen`, `fread`, `fwrite`, `fclose`, `open`, `close`, `read`, `write`, `socket`, `bind`, `listen`, `accept`, `connect`, `pthread_*`, `sem_*`

```c
// ❌ VIOLATION - Critical (Rule 20)
FILE *f = fopen("data.txt", "r");
fread(buffer, 1, size, f);  // Return value ignored!

// ✅ COMPLIANT
FILE *f = fopen("data.txt", "r");
if (f == NULL)
{
    log_error("Failed to open file: %s", strerror(errno));
    return ERROR_FILE_OPEN;
}
size_t bytes = fread(buffer, 1, size, f);
if (bytes != size)
{
    log_error("Read incomplete: expected %zu, got %zu", size, bytes);
    fclose(f);
    return ERROR_READ_INCOMPLETE;
}
```

**Why:** Unchecked return values hide failures, leading to undefined behavior, data corruption, or security vulnerabilities.

---

### Rule 21: Prevent Buffer Overflows

Never use unbounded string functions. Always specify buffer limits.

**Banned functions:** `strcpy`, `strcat`, `sprintf`, `gets`
**Safe alternatives:** `strncpy`, `strncat`, `snprintf`, `fgets`

```c
// ❌ VIOLATION - Critical (Rule 21)
char dest[10];
strcpy(dest, user_input);  // No bounds checking!

// ✅ COMPLIANT - Option 1: strncpy
char dest[10];
strncpy(dest, user_input, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';  // Ensure null termination

// ✅ COMPLIANT - Option 2: snprintf (preferred)
char dest[10];
snprintf(dest, sizeof(dest), "%s", user_input);
```

**Why:** Buffer overflows are the #1 source of security vulnerabilities in C code (CWE-120, CWE-121).

---

### Rule 22: Prevent Null Pointer Dereference

Always validate pointers before use.

```c
// ❌ VIOLATION - Critical (Rule 22)
void process(Data *data)
{
    int value = data->field;  // Crash if data is NULL!
}

// ✅ COMPLIANT
void process(Data *data)
{
    if (data == NULL)
    {
        log_error("Null pointer passed to process()");
        return;
    }
    int value = data->field;
}
```

**Why:** Null dereference causes crashes (SIGSEGV) and can be exploited for denial-of-service attacks.

---

### Rule 23: Free All Allocated Resources

Every allocation must have a corresponding free. Handle early returns carefully.

```c
// ❌ VIOLATION - Critical (Rule 23) - Memory leak on error path
void process_file(const char *path)
{
    FILE *f = fopen(path, "r");
    char *buffer = malloc(1024);
    
    if (validate_file(f) != OK)
    {
        return;  // LEAK: f and buffer not freed!
    }
    
    free(buffer);
    fclose(f);
}

// ✅ COMPLIANT - Goto cleanup pattern
void process_file(const char *path)
{
    FILE *f = NULL;
    char *buffer = NULL;
    int result = ERROR;
    
    f = fopen(path, "r");
    if (f == NULL)
    {
        goto cleanup;
    }
    
    buffer = malloc(1024);
    if (buffer == NULL)
    {
        goto cleanup;
    }
    
    if (validate_file(f) != OK)
    {
        goto cleanup;
    }
    
    // ... process ...
    result = OK;
    
cleanup:
    free(buffer);  // free(NULL) is safe
    if (f != NULL)
    {
        fclose(f);
    }
    return result;
}
```

**Why:** Memory leaks degrade performance over time and can crash long-running systems.

---

### Rule 24: Prevent Use-After-Free

Never access memory after it has been freed. Set pointers to NULL after free.

```c
// ❌ VIOLATION - Critical (Rule 24)
char *data = malloc(100);
strcpy(data, "sensitive");
free(data);
printf("%s", data);  // USE AFTER FREE!

// ✅ COMPLIANT
char *data = malloc(100);
if (data != NULL)
{
    strcpy(data, "sensitive");
    // ... use data ...
    memset(data, 0, 100);  // Clear sensitive data
    free(data);
    data = NULL;  // Prevent accidental reuse
}
```

**Why:** Use-after-free is a critical security vulnerability (CWE-416) that can lead to arbitrary code execution.

---

### Rule 25: Initialize All Variables

All variables must be initialized before use.

```c
// ❌ VIOLATION - Critical (Rule 25)
int count;
if (condition)
{
    count = 10;
}
return count;  // Uninitialized if condition is false!

// ✅ COMPLIANT
int count = 0;  // Default value
if (condition)
{
    count = 10;
}
return count;
```

**Why:** Uninitialized memory contains garbage values, causing undefined behavior and potential security issues.

---

### Rule 26: Avoid Insecure APIs

Do not use insecure or deprecated functions.

| Insecure | Secure Alternative |
|----------|-------------------|
| `rand()` | `getrandom()`, `arc4random()` |
| `gets()` | `fgets()` |
| `strcpy()` | `strncpy()`, `strlcpy()` |
| `sprintf()` | `snprintf()` |
| `getpw()` | `getpwuid_r()` |

```c
// ❌ VIOLATION - Critical (Rule 26)
int secret = rand();  // Predictable!

// ✅ COMPLIANT
uint32_t secret;
if (getrandom(&secret, sizeof(secret), 0) != sizeof(secret))
{
    return ERROR_RANDOM;
}
```

---

## Major Rules (Requires Review) 🟡

### Rule 30: Avoid Narrowing Conversions

Check for overflow when converting to smaller types.

```c
// ❌ VIOLATION - Major (Rule 30)
int64_t big_value = get_large_number();
int small_value = big_value;  // Silent truncation!

// ✅ COMPLIANT
int64_t big_value = get_large_number();
if (big_value > INT_MAX || big_value < INT_MIN)
{
    log_error("Value out of range: %lld", big_value);
    return ERROR_OVERFLOW;
}
int small_value = (int)big_value;  // Explicit cast after check
```

---

### Rule 31: Consistent Parameter Names

Function declaration and definition parameter names must match.

```c
// ❌ VIOLATION - Major (Rule 31)
// In header:
int process(int count, char *buffer);
// In source:
int process(int n, char *buf)  // Different names!
{
    // ...
}

// ✅ COMPLIANT
// In header:
int process(int count, char *buffer);
// In source:
int process(int count, char *buffer)
{
    // ...
}
```

---

### Rule 32: No Redundant Code

Remove unreachable, duplicate, or redundant code.

```c
// ❌ VIOLATION - Major (Rule 32)
if (x > 0)
{
    return 1;
}
else if (x > 0)  // Redundant - can never be true here
{
    return 2;
}

// ✅ COMPLIANT
if (x > 0)
{
    return 1;
}
else if (x < 0)
{
    return -1;
}
return 0;
```

---

### Rule 33: Prevent Infinite Loops

Ensure all loops have a reachable exit condition.

```c
// ❌ VIOLATION - Major (Rule 33)
while (1)
{
    process();
    if (should_stop)
    {
        continue;  // Never exits!
    }
}

// ✅ COMPLIANT
while (!should_stop)
{
    process();
}
```

---

### Rule 34: Thread Safety

Use thread-safe functions in multi-threaded code.

```c
// ❌ VIOLATION - Major (Rule 34)
char *home = getenv("HOME");  // Not thread-safe

// ✅ COMPLIANT (POSIX)
char home[PATH_MAX];
char *env_val = getenv("HOME");  // Still not ideal
if (env_val != NULL)
{
    strncpy(home, env_val, sizeof(home) - 1);
    home[sizeof(home) - 1] = '\0';
}
```

---

### Rule 35: Avoid Performance Issues

Avoid unnecessary copies and allocations.

```c
// ❌ VIOLATION - Major (Rule 35) - C++
void process(std::string s);  // Copies entire string

// ✅ COMPLIANT - C++
void process(const std::string &s);  // No copy
```

---

## Minor Rules (Style Warnings) 🟢

### Rule 40: Consistent Brace Style

Use Allman style (opening brace on new line).

```c
// ❌ VIOLATION - Minor (Rule 40)
if (condition) {
    do_something();
}

// ✅ COMPLIANT
if (condition)
{
    do_something();
}
```

---

### Rule 41: Naming Conventions

Follow consistent naming:
- **Functions:** `lower_case`
- **Variables:** `lower_case`
- **Constants/Macros:** `UPPER_CASE`
- **Types (struct, enum):** `CamelCase`

```c
// ❌ VIOLATION - Minor (Rule 41)
int MyVariable;
void ProcessData();
#define max_size 100

// ✅ COMPLIANT
int my_variable;
void process_data();
#define MAX_SIZE 100
```

---

### Rule 42: Always Use Braces

Use braces even for single-statement blocks.

```c
// ❌ VIOLATION - Minor (Rule 42)
if (error)
    return -1;

// ✅ COMPLIANT
if (error)
{
    return -1;
}
```

---

### Rule 43: Simplify Boolean Expressions

Avoid redundant boolean comparisons.

```c
// ❌ VIOLATION - Minor (Rule 43)
if (flag == true)
if (ptr != NULL)

// ✅ COMPLIANT
if (flag)
if (ptr)
```

---

### Rule 44: Avoid Else After Return

Remove unnecessary else after return statements.

```c
// ❌ VIOLATION - Minor (Rule 44)
if (error)
{
    return -1;
}
else
{
    process();
}

// ✅ COMPLIANT
if (error)
{
    return -1;
}
process();
```

---

## Validation Commands

```bash
# Check formatting
clang-format --dry-run --Werror src/**/*.c src/**/*.h

# Run static analysis
clang-tidy src/**/*.c -- -I./include

# Run validation script
./scripts/validate.sh src/
```

## Suppressing Warnings

```c
// Suppress single line
malloc(size);  // NOLINT(clang-analyzer-unix.Malloc)

// Suppress block
// NOLINTBEGIN(bugprone-unused-return-value)
legacy_function();
// NOLINTEND(bugprone-unused-return-value)

// Suppress entire file (add at top)
// NOLINTFILE(check-name)
```

**Always add a comment explaining why suppression is necessary.**

---

## References

- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [clang-tidy Checks](https://clang.llvm.org/extra/clang-tidy/checks/list.html)
- [MISRA C Guidelines](https://www.misra.org.uk/)
