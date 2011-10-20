/*
 * file2c.c
 * (C) 2010, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_symbol(const char *name)
{
    fputs("data_", stdout);
    for (int i = 0; name[i]; i++)
    {
        if (isalnum(name[i]))
        {
            fputc(name[i], stdout);
        }
        else
        {
            fputc('_', stdout);
        }
    }
}

static bool match_suffix(const char *name, const char *suffix)
{
    size_t suffix_len = strlen(suffix);
    size_t name_len = strlen(name);
    if (name_len <= suffix_len)
    {
        return false;
    }
    return (strcmp(name + name_len - suffix_len, suffix) == 0);
}

static bool should_optimise(const char *name)
{
    return (match_suffix(name, ".html") ||
            match_suffix(name, ".css") ||
            match_suffix(name, ".js"));
}

static int string_compare(const void *a, const void *b)
{
    const char *a1 = *((const char **)a);
    const char *b1 = *((const char **)b);
    return strcmp(a1, b1);
}

int main(int argc, char **argv)
{
    qsort(argv+1, argc-1, sizeof(char *), string_compare);

    fputs("/* GENERATED CODE -- DO NOT EDIT */\n\n", stdout);
    for (int i = 1; i < argc; i++)
    {
        FILE *file = fopen(argv[i], "r");
        if (file == NULL)
        {
            fprintf(stderr, "unable to open file \"%s\" for reading: %s\n",
                argv[i], strerror(errno));
            return EXIT_FAILURE;
        }
       
        printf("/* GENERATED FROM FILE \"%s\" */\n", argv[i]);
        fputs("#ifndef SKIP_", stdout);
        print_symbol(argv[i]);
        fputs("\nstatic const char ", stdout);
        print_symbol(argv[i]);
        fputs("[] =\n{\n", stdout);
        bool ws = true;
        bool optimise = should_optimise(argv[i]);
        while (true)
        {
            char c = getc(file);
            if (c == EOF)
            {
                if (ferror(file))
                {
                    fprintf(stderr, "unable to read from file \"%s\": %s\n",
                        argv[i], strerror(errno));
                    return EXIT_FAILURE;
                }
                if (feof(file))
                {
                    break;
                }
            }

            // Simple whitespace optimisation.
            if (optimise && isspace(c))
            {
                if (ws)
                {
                    continue;
                }
                ws = true;
            }
            else
            {
                ws = false;
            }
            printf("\t0x%.2X,\n", c & 0xFF);
        }
        fclose(file);
        fputs("};\n", stdout);
        fputs("#endif\n\n", stdout);
    }

    fputs("/* GENERATED LOOKUP TABLE */\n", stdout);
    fputs("struct file_data_s\n", stdout);
    fputs("{\n", stdout);
    fputs("\tconst char *name;\n", stdout);
    fputs("\tconst struct http_buffer_s buff;\n", stdout);
    fputs("};\n", stdout);
    fputs("static int file_data_s_compare(const void *a, const void *b)\n",
        stdout);
    fputs("{\n", stdout);
    fputs("\tconst struct file_data_s *a1 = (const struct file_data_s *)a;\n",
        stdout);
    fputs("\tconst struct file_data_s *b1 = (const struct file_data_s *)b;\n",
        stdout);
    fputs("\treturn strcmp(a1->name, b1->name);\n", stdout);
    fputs("}\n", stdout);
    fputs("static const struct file_data_s file_data[] =\n{\n", stdout);
    for (int i = 1; i < argc; i++)
    {
        fputs("#ifndef SKIP_", stdout);
        print_symbol(argv[i]);
        printf("\n\t{\"%s\", {false, 0, sizeof(", argv[i]);
        print_symbol(argv[i]);
        fputs("), sizeof(", stdout);
        print_symbol(argv[i]);
        fputs("), (char *)", stdout);
        print_symbol(argv[i]);
        fputs("}},\n", stdout);
        fputs("#endif\n", stdout);
    }
    fputs("};\n", stdout);

    return EXIT_SUCCESS;
}

