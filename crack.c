#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

#if __has_include("fileutil.h")
#include "fileutil.h"
#endif

#define PASS_LEN 50     // Maximum length any password will be.
#define HASH_LEN 33     // Length of hash plus one for null.


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        printf("Usage: %s hash_file dictionary_file\n", argv[0]);
        exit(1);
    }

    // Read the hashes file into an array.
    int size;
    char **hashes = loadFileAA(argv[1], &size);

    if (size == 0) {
        printf("No hashes loaded.\n");
        exit(1);
    }
    
    // Open the password file for reading.
    FILE *dictFile = fopen(argv[2], "r");
    if (!dictFile) {
        printf("Dictionary file could not be opened.");
        exit(1);
    }

    char password[PASS_LEN];
    int count = 0;

    // For each password, hash it, then use the array search

    while (fgets(password, PASS_LEN, dictFile)) {
        
        // Remove newline if there is one
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0';
        }

        // Hash password
        char *hash = md5(password, len);

        // Linear search for the hash in the hashes array, display and increment count if found
        if (hash) {
            printf("Generated hash for password '%s': %s\n", password, hash);
            
            if(exactStringSearchAA(hash, hashes, size)) {
                printf("Match found: %s %s \n", password, hash);
                count++;
            }
            free(hash);

        } else {
            printf("MD5 failed for password: %s\n", password);
        }
    }

    // Close file and free up memory
    fclose(dictFile);
    freeAA(hashes, size);

    // Display number of matches
    printf("Total matches found: %d\n", count);
    return 0;
}