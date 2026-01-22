/**
 * @file compliant.c
 * @brief Example of code that passes all safety-critical checks.
 *
 * This file demonstrates compliant code patterns for each rule.
 * Run: clang-tidy compliant.c -- to verify no warnings.
 *
 * Rules demonstrated:
 * - Rule 20: Check all return values
 * - Rule 21: Prevent buffer overflows
 * - Rule 22: Prevent null pointer dereference
 * - Rule 23: Free all allocated resources
 * - Rule 24: Prevent use-after-free
 * - Rule 25: Initialize all variables
 * - Rule 30: Avoid narrowing conversions
 * - Rule 40-46: Style rules
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Rule 41: Constants use UPPER_CASE */
#define BUFFER_SIZE     256
#define MAX_NAME_LENGTH 64
#define MAX_PATH_LENGTH 4096

/* Rule 41: Types use CamelCase */
typedef struct FileData
{
    char   *content;
    size_t  size;
    int     valid;
} FileData;

typedef enum ErrorCode
{
    ERROR_NONE           = 0,
    ERROR_NULL_PARAM     = -1,
    ERROR_FILE_OPEN      = -2,
    ERROR_FILE_READ      = -3,
    ERROR_MEMORY         = -4,
    ERROR_OVERFLOW       = -5,
    ERROR_INVALID_INPUT  = -6
} ErrorCode;

/**
 * @brief Safely copy a string with bounds checking.
 *
 * Rule 20 Compliant: Returns status code
 * Rule 21 Compliant: Uses bounded copy
 * Rule 22 Compliant: Validates pointers
 *
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source string
 * @return Number of characters copied, or -1 on error
 */
int safe_string_copy(char *dest, size_t dest_size, const char *src)
{
    /* Rule 22: Validate input pointers */
    if (dest == NULL || src == NULL)
    {
        return ERROR_NULL_PARAM;
    }

    /* Rule 22: Validate buffer size */
    if (dest_size == 0)
    {
        return ERROR_INVALID_INPUT;
    }

    /* Rule 25: Initialize length variable */
    size_t src_len = strlen(src);

    /* Rule 21: Bounds checking before copy */
    if (src_len >= dest_size)
    {
        /* Truncate with warning (could also return error) */
        src_len = dest_size - 1;
    }

    /* Rule 21: Use safe copy with explicit size */
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';  /* Ensure null termination */

    return (int)src_len;
}

/**
 * @brief Read a configuration file safely.
 *
 * Rule 20 Compliant: All return values checked
 * Rule 22 Compliant: Null pointers validated
 * Rule 23 Compliant: Resources properly freed on all paths
 *
 * @param filename Path to the file
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Bytes read on success, negative error code on failure
 */
int read_config_file(const char *filename, char *buffer, size_t buffer_size)
{
    /* Rule 22: Validate input pointers */
    if (filename == NULL || buffer == NULL)
    {
        fprintf(stderr, "Error: NULL parameter passed to read_config_file\n");
        return ERROR_NULL_PARAM;
    }

    /* Rule 22: Validate buffer size */
    if (buffer_size == 0)
    {
        fprintf(stderr, "Error: Buffer size is zero\n");
        return ERROR_INVALID_INPUT;
    }

    /* Rule 20: Check fopen return value */
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n",
                filename, strerror(errno));
        return ERROR_FILE_OPEN;
    }

    /* Rule 20: Check fread return value */
    size_t bytes_read = fread(buffer, 1, buffer_size - 1, file);

    /* Rule 20: Check for read errors */
    if (ferror(file))
    {
        fprintf(stderr, "Error: Read failed for '%s': %s\n",
                filename, strerror(errno));
        fclose(file);  /* Rule 23: Clean up on error path */
        return ERROR_FILE_READ;
    }

    /* Rule 21: Ensure null termination */
    buffer[bytes_read] = '\0';

    /* Rule 23: Close file handle */
    /* Rule 20: Check fclose return value */
    if (fclose(file) != 0)
    {
        fprintf(stderr, "Warning: Failed to close file '%s': %s\n",
                filename, strerror(errno));
        /* Non-fatal, continue with data we read */
    }

    return (int)bytes_read;
}

/**
 * @brief Process data with proper resource management.
 *
 * Rule 23 Compliant: Uses goto cleanup pattern
 * Rule 24 Compliant: Sets pointer to NULL after free
 *
 * @param input Input string to process
 * @return ERROR_NONE on success, negative error code on failure
 */
int process_data(const char *input)
{
    /* Rule 25: Initialize all variables */
    int    result = ERROR_MEMORY;
    char  *buffer = NULL;

    /* Rule 22: Validate input */
    if (input == NULL)
    {
        return ERROR_NULL_PARAM;
    }

    /* Rule 20: Check malloc return value */
    buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    /* Safe copy with bounds checking */
    if (safe_string_copy(buffer, BUFFER_SIZE, input) < 0)
    {
        fprintf(stderr, "Error: String copy failed\n");
        goto cleanup;
    }

    /* Process the data */
    printf("Processed: %s\n", buffer);
    result = ERROR_NONE;

cleanup:
    /* Rule 23 & 24: Free memory and prevent use-after-free */
    free(buffer);
    buffer = NULL;  /* Rule 24: Prevent accidental reuse */

    return result;
}

/**
 * @brief Safely convert a long value to int with overflow check.
 *
 * Rule 30 Compliant: Checks for overflow before narrowing
 *
 * @param large_value Value to convert
 * @param out_value Output pointer for converted value
 * @return ERROR_NONE on success, ERROR_OVERFLOW if value out of range
 */
int convert_long_to_int(long large_value, int *out_value)
{
    /* Rule 22: Validate output pointer */
    if (out_value == NULL)
    {
        return ERROR_NULL_PARAM;
    }

    /* Rule 30: Check for overflow before narrowing */
    if (large_value > INT_MAX || large_value < INT_MIN)
    {
        fprintf(stderr, "Error: Value %ld out of int range\n", large_value);
        return ERROR_OVERFLOW;
    }

    /* Safe to cast after validation */
    *out_value = (int)large_value;
    return ERROR_NONE;
}

/**
 * @brief Allocate and initialize a FileData structure.
 *
 * Demonstrates proper allocation and initialization patterns.
 *
 * @param size Size of content buffer to allocate
 * @return Pointer to allocated structure, or NULL on failure
 */
FileData *create_file_data(size_t size)
{
    /* Rule 22: Validate input */
    if (size == 0)
    {
        return NULL;
    }

    /* Rule 20: Check malloc return value */
    FileData *data = malloc(sizeof(FileData));
    if (data == NULL)
    {
        return NULL;
    }

    /* Rule 25: Initialize all fields */
    data->content = NULL;
    data->size    = 0;
    data->valid   = 0;

    /* Rule 20: Check malloc return value */
    data->content = malloc(size);
    if (data->content == NULL)
    {
        free(data);  /* Rule 23: Clean up partial allocation */
        return NULL;
    }

    /* Rule 25: Initialize allocated buffer */
    memset(data->content, 0, size);
    data->size  = size;
    data->valid = 1;

    return data;
}

/**
 * @brief Free a FileData structure and all its resources.
 *
 * Rule 23 Compliant: Frees all allocated memory
 * Rule 24 Compliant: Clears pointer after free
 *
 * @param data Pointer to pointer to FileData (set to NULL after free)
 */
void destroy_file_data(FileData **data)
{
    /* Rule 22: Validate pointers */
    if (data == NULL || *data == NULL)
    {
        return;
    }

    /* Rule 23: Free nested allocation first */
    if ((*data)->content != NULL)
    {
        /* Clear sensitive data before freeing */
        memset((*data)->content, 0, (*data)->size);
        free((*data)->content);
        (*data)->content = NULL;  /* Rule 24 */
    }

    /* Rule 23: Free the structure */
    free(*data);

    /* Rule 24: Set caller's pointer to NULL */
    *data = NULL;
}

/**
 * @brief Main function demonstrating compliant patterns.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on error
 */
int main(void)
{
    /* Rule 25: Initialize all variables */
    int        result     = EXIT_SUCCESS;
    char       config[BUFFER_SIZE];
    int        bytes_read = 0;
    FileData  *data       = NULL;

    printf("=== C/C++ Code Standards Compliance Demo ===\n\n");

    /* Demo: Safe file reading */
    printf("1. Reading config file...\n");
    bytes_read = read_config_file("config.txt", config, sizeof(config));
    if (bytes_read >= 0)
    {
        printf("   Read %d bytes\n", bytes_read);
    }
    else
    {
        printf("   File not found (expected in demo)\n");
    }

    /* Demo: Safe data processing */
    printf("\n2. Processing data...\n");
    if (process_data("Hello, World!") == ERROR_NONE)
    {
        printf("   Processing complete\n");
    }

    /* Demo: Safe type conversion */
    printf("\n3. Safe type conversion...\n");
    int converted = 0;  /* Rule 25: Initialize */
    if (convert_long_to_int(42L, &converted) == ERROR_NONE)
    {
        printf("   Converted value: %d\n", converted);
    }

    /* Demo: Resource management */
    printf("\n4. Resource management...\n");
    data = create_file_data(1024);
    if (data != NULL)
    {
        printf("   Allocated FileData with %zu byte buffer\n", data->size);
        destroy_file_data(&data);  /* data is now NULL */
        printf("   Resources freed, pointer is %s\n",
               data == NULL ? "NULL (safe)" : "NOT NULL (bug!)");
    }

    printf("\n=== All demos completed successfully ===\n");

    return result;
}
