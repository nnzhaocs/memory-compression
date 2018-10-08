
	global asm_call_interrupt
	section .text
asm_call_interrupt:
	int 0xFA

	section .data
message: db    "asm_call_interrupt is called", 10
