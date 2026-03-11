.word stack_top     // Address of the stack_top
.word _start // Address of the _start label

// The thumb_func is used to make sure the function is in thumb mode,
// which is required for the Cortex-M0+.
.thumb_func
.global _start

_start:
    BL main
    B .
