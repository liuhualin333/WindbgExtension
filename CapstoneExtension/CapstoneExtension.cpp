// CapstoneExtension.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>
#include <dbgeng.h>
#include <string.h>
#include <wdbgexts.h>
#include "capstone.h"
#include <inttypes.h>
//Functions used by cstool
void print_string_hex(PDEBUG_CONTROL debugControl, char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "%s", comment);
	for (c = str; c < str + len; c++) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "0x%02x ", *c & 0xff);
	}

	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "\n");
}

// convert hexchar to hexnum
static uint8_t char_to_hexnum(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t)(c - '0');
	}

	if (c >= 'a' && c <= 'f') {
		return (uint8_t)(10 + c - 'a');
	}

	//  c >= 'A' && c <= 'F'
	return (uint8_t)(10 + c - 'A');
}

// convert user input (char[]) to uint8_t[], each element of which is
// valid hexadecimal, and return actual length of uint8_t[] in @size.
static uint8_t *preprocess(char *code, size_t *size)
{
	size_t i = 0, j = 0;
	uint8_t high, low;
	uint8_t *result;

	result = (uint8_t *)malloc(strlen(code));
	if (result != NULL) {
		while (code[i] != '\0') {
			if (isxdigit(code[i]) && isxdigit(code[i + 1])) {
				high = 16 * char_to_hexnum(code[i]);
				low = char_to_hexnum(code[i + 1]);
				result[j] = high + low;
				i++;
				j++;
			}
			i++;
		}
		*size = j;
	}

	return result;
}

static void usage(PDEBUG_CONTROL debugControl, char *prog)
{
	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "Cstool for Capstone Disassembler Engine");
	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "Syntax: %s [-d] <arch+mode> <assembly-hexstring> [start-address-in-hex-format]\n", prog);
	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "\nThe following <arch+mode> options are supported:\n");

	if (cs_support(CS_ARCH_X86)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        x16:       16-bit mode (X86)\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        x32:       32-bit mode (X86)\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        x64:       64-bit mode (X86)\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        x16att:    16-bit mode (X86) syntax-att\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        x32att:    32-bit mode (X86) syntax-att\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        x64att:    64-bit mode (X86) syntax-att\n");
	}

	if (cs_support(CS_ARCH_ARM)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        arm:       arm\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        armb:      arm + big endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        arml:      arm + little endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        thumb:     thumb mode\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        thumbbe:   thumb + big endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        thumble:   thumb + billtle endian\n");
	}

	if (cs_support(CS_ARCH_ARM64)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        arm64:     aarch64 mode\n");
	}

	if (cs_support(CS_ARCH_MIPS)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        mips:      mips32 + little endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        mipsbe:    mips32 + big endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        mips64:    mips64 + little endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        mips64be:  mips64 + big endian\n");
	}

	if (cs_support(CS_ARCH_PPC)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        ppc64:     ppc64 + little endian\n");
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        ppc64be:   ppc64 + big endian\n");
	}

	if (cs_support(CS_ARCH_SPARC)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        sparc:     sparc\n");
	}

	if (cs_support(CS_ARCH_SYSZ)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        systemz:   systemz (s390x)\n");
	}

	if (cs_support(CS_ARCH_XCORE)) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "        xcore:     xcore\n");
	}

	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "\n");
}

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{

	// 
	// We're version 1.0 of our extension DLL
	// 
	*Version = DEBUG_EXTENSION_VERSION(1, 0);

	// 
	// Flags must be zero
	// 
	*Flags = 0;

	// 
	// Done!
	// 
	return S_OK;
}

HRESULT CALLBACK cstool(PDEBUG_CLIENT4 Client, PCSTR args)
{
	//variables used by capstone
	cs_err err;
	cs_mode md;
	cs_arch arch;
	char *mode;
	bool detail_flag = false;
	csh handle;
	cs_insn *insn;
	uint8_t *assembly;
	uint64_t address = 0;
	size_t count, size;
	uint8_t* str2;
	size_t j = 0;

	int delimiterFlag = 0;
	int argc = 0;//argument count (exclude function name cstool)
	char* argv[10];//string array for arguments
	char* argument = (char *)args;//pointer point to arguments

	EXT_API_VERSION g_ExtApiVersion = { 1,1,EXT_API_VERSION_NUMBER,0 };
	WINDBG_EXTENSION_APIS ExtensionApis = { 0 };
	PDEBUG_CONTROL debugControl;
	HRESULT        hr;
	UNREFERENCED_PARAMETER(args);

	//Get control interface
	hr = Client->QueryInterface
		(__uuidof(IDebugControl),
			(void **)&debugControl);

	if (hr != S_OK) {
		return hr;
	}

	//Split the string using whitespace as delimeters and store it in the argv array
	char* argument_list = strtok(argument," ");
	argv[argc] = (char *)malloc(sizeof(char) * strlen(argument_list));
	strcpy(argv[argc],argument_list);
	argc += 1;
	while (argument_list != NULL)
	{
		argument_list = strtok(NULL, " ");
		if (argument_list == NULL) {
			break;
		}
		//TODO recognize the "0x90 0x91" pattern
		argv[argc] = (char *)malloc(sizeof(char) * strlen(argument_list));
		strcpy(argv[argc], argument_list);
		argc += 1;
	}

	//argument recognition code copied from cstool.c from capstone project
	if (argc != 2 && argc != 3 && argc != 4) {
		usage(debugControl, "cstool");
		debugControl->Release();
		return hr;
	}

	if (!strcmp(argv[0], "-d")) {
		if (argc == 2) {
			usage(debugControl, "cstool");
			debugControl->Release();
			return hr;
		}
		detail_flag = true;
		mode = argv[0];
		assembly = preprocess(argv[2], &size);
		if (argc == 4) {
			char *temp;
			address = strtoull(argv[3], &temp, 16);
			if (temp == argv[3] || *temp != '\0' || errno == ERANGE) {
				debugControl->Output
					(DEBUG_OUTCTL_ALL_CLIENTS, "ERROR: invalid address argument, quit!\n");
				debugControl->Release();
				return hr;
			}
		}
	}
	else {
		if (argc == 4) {
			usage(debugControl, "cstool");
			debugControl->Release();
			return hr;
		}

		mode = argv[0];
		assembly = preprocess(argv[1], &size);
		if (assembly == NULL) {
			debugControl->Output
				(DEBUG_OUTCTL_ALL_CLIENTS, "ERROR: invalid assembler-string argument, quit!\n");
			debugControl->Release();
			return hr;
		}

		if (argc == 3) {
			// cstool <arch> <assembly> <address>
			char *temp;
			address = strtoull(argv[2], &temp, 16);
			if (temp == argv[2] || *temp != '\0' || errno == ERANGE) {
				debugControl->Output
					(DEBUG_OUTCTL_ALL_CLIENTS, "ERROR: invalid address argument, quit!\n");
				debugControl->Release();
				return hr;
			}
		}
	}

	if (!strcmp(mode, "arm")) {
		arch = CS_ARCH_ARM;
		err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
	}

	if (!strcmp(mode, "armb")) {
		arch = CS_ARCH_ARM;
		err = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM + CS_MODE_BIG_ENDIAN), &handle);
	}

	if (!strcmp(mode, "arml")) {
		arch = CS_ARCH_ARM;
		err = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN), &handle);
	}

	if (!strcmp(mode, "thumb")) {
		arch = CS_ARCH_ARM;
		err = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN), &handle);
	}

	if (!strcmp(mode, "thumbbe")) {
		arch = CS_ARCH_ARM;
		err = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB + CS_MODE_BIG_ENDIAN), &handle);
	}

	if (!strcmp(mode, "thumble")) {
		arch = CS_ARCH_ARM;
		err = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN), &handle);
	}

	if (!strcmp(mode, "arm64")) {
		arch = CS_ARCH_ARM64;
		err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode, "mips")) {
		arch = CS_ARCH_MIPS;
		err = cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN), &handle);
	}

	if (!strcmp(mode, "mipsbe")) {
		arch = CS_ARCH_MIPS;
		err = cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN), &handle);
	}

	if (!strcmp(mode, "mips64")) {
		arch = CS_ARCH_MIPS;
		err = cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN), &handle);
	}

	if (!strcmp(mode, "mips64be")) {
		arch = CS_ARCH_MIPS;
		err = cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN), &handle);
	}

	if (!strcmp(mode, "x16")) {
		md = CS_MODE_16;
		arch = CS_ARCH_X86;
		err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
	}

	if (!strcmp(mode, "x32")) {
		md = CS_MODE_32;
		arch = CS_ARCH_X86;
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	}

	if (!strcmp(mode, "x64")) {
		md = CS_MODE_64;
		arch = CS_ARCH_X86;
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	}

	if (!strcmp(mode, "x16att")) {
		md = CS_MODE_16;
		arch = CS_ARCH_X86;
		err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
		if (!err) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		}
	}

	if (!strcmp(mode, "x32att")) {
		md = CS_MODE_32;
		arch = CS_ARCH_X86;
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
		if (!err) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		}
	}

	if (!strcmp(mode, "x64att")) {
		md = CS_MODE_64;
		arch = CS_ARCH_X86;
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
		if (!err) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		}
	}

	if (!strcmp(mode, "ppc64")) {
		arch = CS_ARCH_PPC;
		err = cs_open(CS_ARCH_PPC, (cs_mode)(CS_MODE_64 + CS_MODE_LITTLE_ENDIAN), &handle);
	}

	if (!strcmp(mode, "ppc64be")) {
		arch = CS_ARCH_PPC;
		err = cs_open(CS_ARCH_PPC, (cs_mode)(CS_MODE_64 + CS_MODE_BIG_ENDIAN), &handle);
	}

	if (!strcmp(mode, "sparc")) {
		arch = CS_ARCH_SPARC;
		err = cs_open(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "systemz") || !strcmp(mode, "sysz") || !strcmp(mode, "s390x")) {
		arch = CS_ARCH_SYSZ;
		err = cs_open(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "xcore")) {
		arch = CS_ARCH_XCORE;
		err = cs_open(CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN, &handle);
	}

	if (err) {
		debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "ERROR: Failed on cs_open(), quit!\n");
		usage(debugControl, "cstool");
		cs_close(&handle);
		debugControl->Release();
		return hr;
	}

	if (detail_flag) {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	//Disassemble the code
	count = cs_disasm(handle, assembly, size, address, 0, &insn);
	if (count > 0) {
		//TODO:	Fix the three separate commands problem: The address always pushes the mnemonic out of place.
		for (j = 0; j < count; j++) {
			debugControl->Output
				(DEBUG_OUTCTL_ALL_CLIENTS, "0x%Ix: ", insn[j].address);
			debugControl->Output
				(DEBUG_OUTCTL_ALL_CLIENTS, "%s ", insn[j].mnemonic);
			debugControl->Output
				(DEBUG_OUTCTL_ALL_CLIENTS, "%s\n",insn[j].op_str);
		}
        cs_free(insn, count);
		cs_close(&handle);
		debugControl->Release();
		return S_OK;
	}
	else {
		debugControl->Output
			(DEBUG_OUTCTL_ALL_CLIENTS,
				"ERROR: Failed to disassemble given code!\n");
		cs_close(&handle);
		debugControl->Release();
		return hr;
	}
}

//Tutorial customized function for how to evaluate a value and print on the debugger screen
HRESULT CALLBACK
mycommand1(PDEBUG_CLIENT4 Client, PCSTR args)
{
	PDEBUG_CONTROL debugControl;
	HRESULT        hr;
	DEBUG_VALUE    result;

	UNREFERENCED_PARAMETER(args);

	// 
	// Let's do a couple of simple things. First
	// thing to do is use the passed in client to
	// access the debugger engine APIs.
	// 
	// First, we'll get an IDebugControl so that we
	// can print messages.
	// 
	hr = Client->QueryInterface
		(__uuidof(IDebugControl),
			(void **)&debugControl);

	if (hr != S_OK) {
		return hr;
	}

	// 
	// Now we can print.
	// 
	debugControl->Output
		(DEBUG_OUTCTL_ALL_CLIENTS,
			"mycommand running...\n");

	// 
	// Use the evaluator to evaluate an expression
	// 
	hr = debugControl->Evaluate("2 + 2",
		DEBUG_VALUE_INT32,
		&result,
		NULL);

	if (hr != S_OK) {
		debugControl->Release();
		return hr;
	}

	debugControl->Output(DEBUG_OUTCTL_ALL_CLIENTS,
		"Result is %d\n", result.I32);


	// 
	// Done with this.
	// 
	debugControl->Release();

	return S_OK;
}
