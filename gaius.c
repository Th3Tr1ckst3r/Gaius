/*
    Gaius - A cryptography tool which implements a new complex mixed substitution
    cipher dubbed 'Gaius Cipher' into binary/plaintext data structures.

    Created by Adrian Tarver(Th3Tr1ckst3r) @ https://github.com/Th3Tr1ckst3r/

////////////////////////////////////////////////////////////////////////////////////////

  IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.

  By downloading, copying, installing, or using the software you agree to this license.
  If you do not agree to this license, do not download, install,
  copy, or use the software.


                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU Affero General Public License is a free, copyleft license for
software and other kinds of works, specifically designed to ensure
cooperation with the community in the case of network server software.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
our General Public Licenses are intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  Developers that use our General Public Licenses protect your rights
with two steps: (1) assert copyright on the software, and (2) offer
you this License which gives you legal permission to copy, distribute
and/or modify the software.

  A secondary benefit of defending all users' freedom is that
improvements made in alternate versions of the program, if they
receive widespread use, become available for other developers to
incorporate.  Many developers of free software are heartened and
encouraged by the resulting cooperation.  However, in the case of
software used on network servers, this result may fail to come about.
The GNU General Public License permits making a modified version and
letting the public access it on a server without ever releasing its
source code to the public.

  The GNU Affero General Public License is designed specifically to
ensure that, in such cases, the modified source code becomes available
to the community.  It requires the operator of a network server to
provide the source code of the modified version running there to the
users of that server.  Therefore, public use of a modified version, on
a publicly accessible server, gives the public access to the source
code of the modified version.

  An older license, called the Affero General Public License and
published by Affero, was designed to accomplish similar goals.  This is
a different license, not a version of the Affero GPL, but Affero has
released a new version of the Affero GPL which permits relicensing under
this license.

  The precise terms and conditions for copying, distribution and
modification follow here:

https://raw.githubusercontent.com/Th3Tr1ckst3r/Gaius/main/LICENSE
*/

#include <sys/stat.h> // For stat, mkdir, and struct stat.
#include <errno.h>    // For errno.
#include <dirent.h>   // For working with directories.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h> // For access() to check file existence.

#define ALPHABET "abcdefghijklmnopqrstuvwxyz"
#define PUNCTUATION "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
#define DEFAULT_BUFFER_SIZE 4096

// Function declarations.
char *base64_encode(const unsigned char *data, size_t input_length);
char *base64_decode(const char *encoded_data, size_t *decoded_length);
void generate_mixed_alphabet(const char *keyword, char *mixed_alphabet, char *punctuation_mapping);
void encrypt(const char *input, const char *mixed_alphabet, const char *punctuation_mapping, char *output);
void decrypt(const char *input, const char *mixed_alphabet, const char *punctuation_mapping, char *output);
int find_index(const char *str, char ch);
void process_text(const char *input, const char *mapping, const char *reverse_mapping, char *output);
int validate_password(const char *password);
int is_directory(const char *path);
void create_directory(const char *path);
void process_directory(const char *mode, const char *keyword, const char *input_dir, const char *output_dir, const char *mixed_alphabet, const char *punctuation_mapping, int disable_base64, int enable_verbosity, int buffer_size);
void process_file(const char *mode, const char *keyword, const char *input_file, const char *output_file, const char *mixed_alphabet, const char *punctuation_mapping, int disable_base64, int enable_verbosity, int buffer_size);

// Function to encode data in Base64.
const char *b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Function to encode raw data in Base64.
char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);  // Output length must be 4 times the size of input
    char *encoded_data = malloc(output_length + 1);  // +1 for null terminator

    if (encoded_data == NULL) return NULL;  // Error checking for malloc failure

    for (size_t i = 0, j = 0; i < input_length;) {
        unsigned long octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        unsigned long octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        unsigned long octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        unsigned long triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = b64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 0 * 6) & 0x3F];
    }

    // Add padding if necessary
    for (int i = 0; i < 3 - (input_length % 3); i++) {
        encoded_data[output_length - 1 - i] = '=';
    }

    encoded_data[output_length] = '\0';  // Null-terminate the string
    return encoded_data;
}

// Function to decode Base64 data into raw data.
char *base64_decode(const char *encoded_data, size_t *decoded_length) {
    size_t len = strlen(encoded_data);
    *decoded_length = (len / 4) * 3;  // The decoded length is 3/4 of the encoded length

    // Handle padding '=' characters
    if (encoded_data[len - 1] == '=') (*decoded_length)--;
    if (encoded_data[len - 2] == '=') (*decoded_length)--;

    char *decoded_data = malloc(*decoded_length);  // Allocate memory for the decoded data
    if (decoded_data == NULL) {
        perror("Failed to allocate memory for decoded data");
        return NULL;
    }

    int i = 0, j = 0;
    unsigned char a, b, c, d;

    // Loop through the encoded data in 4-character blocks
    while (i < len) {
        a = strchr(b64_table, encoded_data[i++]) - b64_table;
        b = strchr(b64_table, encoded_data[i++]) - b64_table;
        c = strchr(b64_table, encoded_data[i++]) - b64_table;
        d = strchr(b64_table, encoded_data[i++]) - b64_table;

        decoded_data[j++] = (a << 2) | (b >> 4);
        if (encoded_data[i - 2] != '=') decoded_data[j++] = (b << 4) | (c >> 2);
        if (encoded_data[i - 1] != '=') decoded_data[j++] = (c << 6) | d;
    }

    return decoded_data;
}

// wrapper for better utilization of our encoding function.
char *encode_data_to_base64(const unsigned char *data, size_t input_length) {
    return base64_encode(data, input_length);
}

// wrapper for better utilization of our decoding function.
char *decode_base64_data(const char *encoded_data, size_t *decoded_length) {
    return base64_decode(encoded_data, decoded_length);
}

// Function to generate a mixed alphabet based on the keyword.
void generate_mixed_alphabet(const char *keyword, char *mixed_alphabet, char *punctuation_mapping) {
    int i, j = 0, used[26] = {0};
    size_t keyword_len = strlen(keyword);
    char unique_chars[26] = {0};
    int punctuation_len = strlen(PUNCTUATION);

    // Initialize mixed alphabet to empty string
    mixed_alphabet[0] = '\0';

    // Add unique characters from the keyword to mixed alphabet
    for (i = 0; i < keyword_len; i++) {
        char ch = tolower(keyword[i]);
        if (isalpha(ch) && !used[ch - 'a']) {
            mixed_alphabet[j++] = ch;
            used[ch - 'a'] = 1;
        }
    }

    // Append remaining characters from the alphabet
    for (i = 0; i < 26; i++) {
        if (!used[i]) {
            mixed_alphabet[j++] = ALPHABET[i];
        }
    }
    mixed_alphabet[j] = '\0';

    // Create punctuation mapping by shuffling punctuation characters
    for (i = 0; i < punctuation_len; i++) {
        punctuation_mapping[i] = PUNCTUATION[i];
    }
    // Shuffle punctuation mapping randomly
    srand(time(NULL));  // Seed random number generator
    for (i = punctuation_len - 1; i > 0; i--) {
        int rand_idx = rand() % (i + 1);
        char temp = punctuation_mapping[i];
        punctuation_mapping[i] = punctuation_mapping[rand_idx];
        punctuation_mapping[rand_idx] = temp;
    }
}

// Function to encrypt text using mixed alphabet and punctuation mapping.
void encrypt(const char *input, const char *mixed_alphabet, const char *punctuation_mapping, char *output) {
    size_t i, len = strlen(input);
    for (i = 0; i < len; i++) {
        char ch = input[i];
        if (isalpha(ch)) {
            int index = strchr(ALPHABET, tolower(ch)) - ALPHABET;
            output[i] = isupper(ch) ? toupper(mixed_alphabet[index]) : mixed_alphabet[index];
        } else if (strchr(PUNCTUATION, ch)) {
            int index = strchr(PUNCTUATION, ch) - PUNCTUATION;
            output[i] = punctuation_mapping[index];
        } else {
            output[i] = ch;  // Non-alphabetic characters are unchanged
        }
    }
    output[i] = '\0';
}

// Function to decrypt text using mixed alphabet and punctuation mapping.
void decrypt(const char *input, const char *mixed_alphabet, const char *punctuation_mapping, char *output) {
    size_t i, len = strlen(input);
    for (i = 0; i < len; i++) {
        char ch = input[i];
        if (isalpha(ch)) {
            int index = strchr(mixed_alphabet, tolower(ch)) - mixed_alphabet;
            output[i] = isupper(ch) ? toupper(ALPHABET[index]) : ALPHABET[index];
        } else if (strchr(punctuation_mapping, ch)) {
            int index = strchr(punctuation_mapping, ch) - punctuation_mapping;
            output[i] = PUNCTUATION[index];
        } else {
            output[i] = ch;  // Non-alphabetic characters are unchanged
        }
    }
    output[i] = '\0';
}

// Function to find the index of a character in a string.
int find_index(const char *str, char ch) {
    char *ptr = strchr(str, ch);
    return (ptr) ? (ptr - str) : -1;
}

// Function to process text for enciphering, or deciphering.
void process_text(const char *input, const char *mapping, const char *reverse_mapping, char *output) {
    size_t i, len = strlen(input);
    for (i = 0; i < len; i++) {
        char ch = input[i];

        // Handle alphabetic characters (both uppercase and lowercase)
        if (isalpha(ch)) {
            int index = find_index(mapping, tolower(ch));
            if (index != -1) {
                output[i] = isupper(ch) ? toupper(reverse_mapping[index]) : reverse_mapping[index];
            }
        }
        // Handle punctuation characters
        else if (strchr(PUNCTUATION, ch)) {
            int index = find_index(mapping, ch);
            if (index != -1) {
                output[i] = reverse_mapping[index];
            } else {
                output[i] = ch;  // If punctuation isn't mapped, just copy the character
            }
        }
        // For other characters (spaces, newlines, etc.), leave them unchanged
        else {
            output[i] = ch;
        }
    }
    output[i] = '\0';  // Null-terminate the output string
}

// Function to validate the keyword/password.
int validate_password(const char *password) {
    int has_special = 0, has_digit = 0, length = strlen(password);

    if (length < 8) {
        return 0; // Password too short
    }

    for (int i = 0; i < length; i++) {
        if (isdigit(password[i])) {
            has_digit = 1;
        }
        if (!isalnum(password[i])) { // Checks for non-alphanumeric (special characters)
            has_special = 1;
        }
    }

    return has_special && has_digit;
}

// Function to check if a path is a directory.
int is_directory(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0; // Path does not exist or error
    }
    return S_ISDIR(path_stat.st_mode);
}

// Function to create a directory if it doesn't exist.
void create_directory(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        perror("Failed to create output directory");
        exit(1);
    }
}

// Function to process a single file.
void process_file(const char *mode, const char *keyword, const char *input_file, const char *output_file, 
                  const char *mixed_alphabet, const char *punctuation_mapping, int disable_base64, int enable_verbosity, int buffer_size) {
    if (enable_verbosity) {
        printf("Processing file: %s\n", input_file);
        printf("Output file: %s\n", output_file);
        printf("Mode: %s\n", mode);
        printf("Base64 Encoding Disabled: %s\n", disable_base64 ? "Yes" : "No");
        printf("Buffer Size: %d bytes\n", buffer_size);
    }

    // Open input and output files
    FILE *input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        perror("Error opening input file");
        return;
    }

    FILE *output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        perror("Error opening output file");
        fclose(input_fp);
        return;
    }

    unsigned char *buffer = malloc(buffer_size);
    unsigned char *processed_buffer = malloc(buffer_size * 2); // Allocate for worst-case size
    if (!buffer || !processed_buffer) {
        perror("Memory allocation failed for buffers");
        free(buffer);
        free(processed_buffer);
        fclose(input_fp);
        fclose(output_fp);
        return;
    }

    size_t bytes_read, bytes_processed;

    while ((bytes_read = fread(buffer, 1, buffer_size, input_fp)) > 0) {
        if (strcmp(mode, "encipher") == 0) {
            if (!disable_base64) {
                // Encode input to Base64 before ciphering
                char *encoded_data = base64_encode(buffer, bytes_read);
                if (!encoded_data) {
                    fprintf(stderr, "Failed to encode data for file: %s\n", input_file);
                    break;
                }
                process_text(encoded_data, mixed_alphabet, ALPHABET, (char *)processed_buffer);
                fwrite(processed_buffer, 1, strlen((char *)processed_buffer), output_fp);
                free(encoded_data);
            } else {
                // Cipher directly without Base64
                process_text((char *)buffer, mixed_alphabet, ALPHABET, (char *)processed_buffer);
                fwrite(processed_buffer, 1, bytes_read, output_fp);
            }
        } else if (strcmp(mode, "decipher") == 0) {
            if (!disable_base64) {
                // Decipher the text
                process_text((char *)buffer, ALPHABET, mixed_alphabet, (char *)processed_buffer);

                // Decode Base64 after ciphering
                size_t decoded_length;
                char *decoded_data = base64_decode((char *)processed_buffer, &decoded_length);
                if (!decoded_data) {
                    fprintf(stderr, "Failed to decode data for file: %s\n", input_file);
                    break;
                }
                fwrite(decoded_data, 1, decoded_length, output_fp);
                free(decoded_data);
            } else {
                // Decipher directly without Base64
                process_text((char *)buffer, ALPHABET, mixed_alphabet, (char *)processed_buffer);
                fwrite(processed_buffer, 1, bytes_read, output_fp);
            }
        } else {
            fprintf(stderr, "Error: Invalid mode for file: %s\n", input_file);
            break;
        }

        if (enable_verbosity) {
            printf("Processed %zu bytes from input file.\n", bytes_read);
        }
    }

    if (enable_verbosity) {
        printf("File processing complete. Output written to: %s\n", output_file);
    }

    // Cleanup
    free(buffer);
    free(processed_buffer);
    fclose(input_fp);
    fclose(output_fp);
}

// Recursive function to process a directory.
void process_directory(const char *mode, const char *keyword, const char *input_dir, const char *output_dir, 
                       const char *mixed_alphabet, const char *punctuation_mapping, int disable_base64, int enable_verbosity, int buffer_size) {
    if (enable_verbosity) {
        printf("Processing directory: %s\n", input_dir);
        printf("Output directory: %s\n", output_dir);
    }

    // Open the input directory
    DIR *dir = opendir(input_dir);
    if (!dir) {
        perror("Failed to open input directory");
        exit(1);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char input_path[1024], output_path[1024];
        snprintf(input_path, sizeof(input_path), "%s/%s", input_dir, entry->d_name);
        snprintf(output_path, sizeof(output_path), "%s/%s", output_dir, entry->d_name);

        if (is_directory(input_path)) {
            // Process subdirectory
            if (enable_verbosity) {
                printf("Found directory: %s\n", input_path);
                printf("Creating output directory: %s\n", output_path);
            }
            create_directory(output_path);
            process_directory(mode, keyword, input_path, output_path, mixed_alphabet, punctuation_mapping, disable_base64, enable_verbosity, buffer_size);
        } else {
            // Process file
            if (enable_verbosity) {
                printf("Found file: %s\n", input_path);
            }
            process_file(mode, keyword, input_path, output_path, mixed_alphabet, punctuation_mapping, disable_base64, enable_verbosity, buffer_size);
        }
    }

    if (enable_verbosity) {
        printf("Finished processing directory: %s\n", input_dir);
    }

    closedir(dir);
}

// Main function to process arguments.
int main(int argc, char *argv[]) {
    int disable_base64 = 0;
    int enable_verbosity = 0;
    int buffer_size = DEFAULT_BUFFER_SIZE;

    // Parse optional flags
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "-n64") == 0) {
            disable_base64 = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            enable_verbosity = 1;
        } else if (strcmp(argv[i], "-chunk") == 0) {
            // Ensure a value follows the "-chunk" flag
            if (i + 1 < argc) {
                buffer_size = atoi(argv[++i]); // Convert the next argument to an integer
                if (buffer_size <= 0) {
                    fprintf(stderr, "Error: Invalid buffer size '%s'. Must be a positive integer.\n", argv[i]);
                    return 1;
                }
                // Ensure the buffer_size is at least 1024 bytes
                if (buffer_size < 1024) {
                    fprintf(stderr, "Error: Buffer size cannot be less than 1024 bytes. Setting to 1024 bytes.\n");
                    buffer_size = 1024;
                }
            } else {
                fprintf(stderr, "Error: Missing value for '-chunk' flag.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown flag '%s'.\n", argv[i]);
            return 1;
        }
    }

    // Validate argument count
    if (argc < 5) {
        fprintf(stderr,
                "Gaius V1.0 - A cryptography tool which implements a new complex mixed substitution cipher dubbed 'Gaius Cipher' into binary/plaintext data structures.\n\n\n"
                "Usage: gaius <encipher|decipher> <password|keyword> <input_file> <output_file> [-n64, -v, -chunk <size>]\n\n"
                "Optional Usage: \n\n"
                "-n64    Disables utilization of base64 in the cipher process.\n"
                "-v      Enables verbose output for debugging.\n"
                "-chunk  Specifies the buffer size for processing files (default: 4096 bytes).\n\n"
                "For more information, including documentation, please visit https://www.github.com/Th3Tr1ckst3r/Gaius\n\n");
        return 1;
    }

    const char *mode = argv[1];
    const char *keyword = argv[2];
    const char *input_path = argv[3];
    const char *output_path = argv[4];

    if (!validate_password(keyword)) {
        fprintf(stderr, "Error: Password must be at least 8 characters long, contain at least 1 special character, and 1 integer.\n");
        return 1;
    }

    if (!is_directory(input_path) && access(input_path, F_OK) == -1) {
        fprintf(stderr, "Error: Input path does not exist.\n");
        return 1;
    }

    if (is_directory(output_path)) {
        create_directory(output_path);
    }

    char mixed_alphabet[27];
    char punctuation_mapping[strlen(PUNCTUATION) + 1];
    generate_mixed_alphabet(keyword, mixed_alphabet, punctuation_mapping);

    if (enable_verbosity) {
        printf("Mode: %s\n", mode);
        printf("Keyword: %s\n", keyword);
        printf("Input Path: %s\n", input_path);
        printf("Output Path: %s\n", output_path);
        printf("Disable Base64: %s\n", disable_base64 ? "Yes" : "No");
        printf("Verbosity Enabled: Yes\n");
        printf("Buffer Size: %d bytes\n", buffer_size);
    }

    if (is_directory(input_path)) {
        create_directory(output_path);
        process_directory(mode, keyword, input_path, output_path, mixed_alphabet, punctuation_mapping, disable_base64, enable_verbosity, buffer_size);
    } else {
        process_file(mode, keyword, input_path, output_path, mixed_alphabet, punctuation_mapping, disable_base64, enable_verbosity, buffer_size);
    }

    return 0;
}
