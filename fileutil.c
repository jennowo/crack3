#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileutil.h"

// For the array of arrays, implement loadFileAA, substringSearchAA, and freeAA.


// Load the text file from the given filename.
// Return a pointer to the array of strings.
// Sets the value of size to be the number of valid entries in the array (not the total array length).
char ** loadFileAA(char *filename, int *size)
{
	FILE *in = fopen(filename, "r");
	if (!in)
	{
	    perror("Can't open file");
	    exit(1);
	}
	
	// Allocate memory for an array of strings (arr).
	int capacity = 10; 									// Initial capacity
	char ** array = malloc(capacity * sizeof(char *));
	*size = 0;

	// Read the file line by line.
	char line[255];
	while(fgets(line, 255, in)) {
		// Trim newline
		int length = strlen(line);
		if (length > 0 && line[length - 1] == '\n') {
            line[length - 1] = '\0';
        }

		//Expand array if necessary (realloc), double size
		if (*size >= capacity) {
			capacity *= 2;
			array = realloc(array, capacity * sizeof(char *));
		}

		// Allocate memory for the string
		array[*size] = malloc(sizeof(line));

		// Copy each line into the string using (strcpy)
		strcpy(array[*size], line);

		// Attach the string to the large array (assignment =)
		(*size)++;

	}
    // Close the file.
	fclose(in);
	
	// The size should be the number of entries in the array.
	// *size = 0;
	
	// Return pointer to the array of strings.
	return array;
}


// Search the array for the target string.
// Return the found string or NULL if not found.
char * substringSearchAA(char *target, char **lines, int size)
{
		for (int i = 0; i < size; i++)
	{
		if (strstr(lines[i], target) != NULL) // Target found in arr[i]
		{
			return lines[i];
		}
	}
	return NULL;
}


// Free the memory used by the array, each string, then whole array
void freeAA(char ** arr, int size)
{
	for (int i = 0; i < size; i++)
	{
		free(arr[i]); 
	}
	free(arr); 
}

// Add a function to perform a linear search using exact string matches (i.e., strcmp). There is an existing function 
// that does partial string matches (strstr); the new one you'll write will be similar.

// Search the array for the target string.
// Return the found string or NULL if not found.
char * exactStringSearchAA(char *target, char **lines, int size)
{
	for (int i = 0; i < size; i++)
	{
		if (strcmp(lines[i], target) == 0) // Exact match returns 0
		{
			return lines[i];
		}
	}
	return NULL;							// No match
}