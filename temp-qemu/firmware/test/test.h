#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <stdlib.h>

// ANSI color codes for colored outputs
#define COLOR_RESET "\033[0m"
#define COLOR_BLUE  "\033[1;34m" // bold
#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"

/*************************
 * Macros for test output
 ************************/

/* Prints start of test alongside test name */
#define TEST_START(name) printf (COLOR_BLUE "[TEST] %s" COLOR_RESET "\n", name)

/* Prints test passed */
#define TEST_PASS() printf ("  -> " COLOR_GREEN "PASSED" COLOR_RESET "\n")

/* Declares the test as failed and exits
 * NOTE: do while needed for use with if statements without "{}"
 * */
#define TEST_FAIL(msg)                                                \
  do                                                                  \
    {                                                                 \
      printf ("  -> " COLOR_RED "FAILED: " COLOR_RESET "%s \n", msg); \
      exit (1);                                                       \
    }                                                                 \
  while (0)

/* Tests if the specified condition is false, prints an error
 * message and exits if so */
#define ASSERT(cond, msg) \
  if (!(cond))            \
  TEST_FAIL (msg)

#endif // TEST_H
