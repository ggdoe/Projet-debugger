#include "tools.h"

extern struct user_regs_struct regs;

static void print_str_eflags(const char* format){
	char str_eflags[48];
	char *label[] = {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF", "IOPL", "NT", "RF", "VM"};
	size_t bit_pos[] = {1<<0, 1<<2, 1<<4, 1<<6, 1<<7, 1<<8, 1<<9, 1<<10, 1<<11, 1<<12, 1<<14, 1<<16, 1<<17};

	// !! IOPL est mal gérer voir wiki

	int written = 0;
	str_eflags[written++] = '['; // présentation comme gdb
	str_eflags[written++] = ' ';

	for(unsigned int i = 0; i < sizeof(label) / sizeof(char*); i++){
		if((regs.eflags & bit_pos[i]) == bit_pos[i]){

			const char *lb = label[i];
			// on copie à la main le label dans str_eflags
			while(*lb != '\0'){
				str_eflags[written++] = *(lb++);
			}

			str_eflags[written++] = ' ';
		}
	}
	str_eflags[written++] = ']';
	str_eflags[written] = '\0';

	printf(format, "eflags", regs.eflags, str_eflags);
}

void print_regs(){
	printf("  %9s %#18llx %23llu\n", "orig_rax", regs.orig_rax, regs.orig_rax);
	printf("  %9s %#18llx %23llu\n", "rax", regs.rax, regs.rax);
	printf("  %9s %#18llx %23llu\n", "rbx", regs.rbx, regs.rbx);
	printf("  %9s %#18llx %23llu\n", "rcx", regs.rcx, regs.rcx);
	printf("  %9s %#18llx %23llu\n", "rdx", regs.rdx, regs.rdx);
	printf("  %9s %#18llx %23llu\n", "rsi", regs.rsi, regs.rsi);
	printf("  %9s %#18llx %23llu\n", "rdi", regs.rdi, regs.rdi);
	printf("  %9s %#18llx %23llu\n", "rbp", regs.rbp, regs.rbp);
	printf("  %9s %#18llx %23llu\n", "rsp", regs.rsp, regs.rsp);
	printf("  %9s %#18llx %23llu\n", "r8", regs.r8, regs.r8);
	printf("  %9s %#18llx %23llu\n", "r9", regs.r9, regs.r9);
	printf("  %9s %#18llx %23llu\n", "r10", regs.r10, regs.r10);
	printf("  %9s %#18llx %23llu\n", "r11", regs.r11, regs.r11);
	printf("  %9s %#18llx %23llu\n", "r12", regs.r12, regs.r12);
	printf("  %9s %#18llx %23llu\n", "r13", regs.r13, regs.r13);
	printf("  %9s %#18llx %23llu\n", "r14", regs.r14, regs.r14);
	printf("  %9s %#18llx %23llu\n", "r15", regs.r15, regs.r15);
	printf("  %9s %#18llx %23llu\n", "rip", regs.rip, regs.rip);
	printf("  %9s %#18llx %23llu\n", "fs_base", regs.fs_base, regs.fs_base);
	printf("  %9s %#18llx %23llu\n", "gs_base", regs.gs_base, regs.gs_base);
	print_str_eflags("  %9s %#18llx %23s\n");
	printf("  %9s %#18llx %23llu\n", "cs", regs.cs, regs.cs);
	printf("  %9s %#18llx %23llu\n", "ss", regs.ss, regs.ss);
	printf("  %9s %#18llx %23llu\n", "ds", regs.ds, regs.ds);
	printf("  %9s %#18llx %23llu\n", "es", regs.es, regs.es);
	printf("  %9s %#18llx %23llu\n", "fs", regs.fs, regs.fs);
	printf("  %9s %#18llx %23llu\n", "gs", regs.gs, regs.gs);
}

void get_sh_flags(Elf64_Xword sh_flags, char* str_flags)
{
	// http://www.sco.com/developers/gabi/latest/ch4.sheader.html#sh_flags
	size_t flags_type[] = {SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHF_STRINGS, SHF_INFO_LINK, SHF_LINK_ORDER, SHF_OS_NONCONFORMING, SHF_GROUP, SHF_TLS, SHF_COMPRESSED, SHF_MASKOS, SHF_MASKPROC};
	char flags_letter[] = {'W', 'A', 'X', 'M', 'S', 'I', 'L', 'O', 'G', 'T', 'C', 'o', 'm'};
	int written = 0;

	// on parcours tous les flags
	for(unsigned int i = 0; i < sizeof(flags_letter); i++){
		// on test si "flags_type[i]" est dans sh_flags
		if((sh_flags & flags_type[i]) == flags_type[i]) 
			// si oui on ajoute son symbole à str_flags
			str_flags[written++] = flags_letter[i]; 
		
		// str_flags ne comporte que 4 éléments max dont \0 
		if(written > 3) break;
	}
	// on null-termine str_flags
	str_flags[written] = '\0';
}

const char* get_sh_type(Elf64_Word sh_type){
	switch(sh_type){
		case SHT_NULL:		return "NULL"; break;
		case SHT_PROGBITS:	return "PROGBITS"; break;
		case SHT_SYMTAB:	return "SYMTAB"; break;
		case SHT_STRTAB:	return "STRTAB"; break;
		case SHT_RELA:		return "RELA"; break;
		case SHT_HASH:		return "HASH"; break;
		case SHT_DYNAMIC:	return "DYNAMIC"; break;
		case SHT_NOTE:		return "NOTE"; break;
		case SHT_NOBITS:	return "NOBITS"; break;
		case SHT_REL:		return "REL"; break;
		case SHT_SHLIB:		return "SHLIB"; break;
		case SHT_DYNSYM:	return "DYNSYM"; break;
		case SHT_LOPROC:	return "LOPROC"; break;
		case SHT_HIPROC:	return "HIPROC"; break;
		case SHT_LOUSER:	return "LOUSER"; break;
		case SHT_HIUSER:	return "HIUSER"; break;
		case SHT_GNU_HASH:	return "GNU_HASH"; break;
		case SHT_GNU_versym: return "VERSYM"; break;
		case SHT_GNU_verneed: return "VERNEED"; break;
		case SHT_INIT_ARRAY: return "INIT_ARRAY"; break;
		case SHT_FINI_ARRAY: return "FINI_ARRAY"; break;
		default:			return "UNKNOWN"; break;
	}
}

// -> man dladdr
const char* get_st_info_type(unsigned char st_info){
	switch(ELF64_ST_TYPE(st_info)){
		case STT_NOTYPE:	return "NOTYPE "; break;
		case STT_OBJECT:	return "OBJECT "; break;
		case STT_FUNC:		return "FUNC   "; break;
		case STT_SECTION:	return "SECTION"; break;
		case STT_FILE:		return "FILE   "; break;
		case STT_COMMON:	return "COMMON "; break;
		case STT_TLS:		return "TLS    "; break;
		case STT_GNU_IFUNC:	return "GNU_IFUNC"; break;
		default: return "UNKOWN ";
	}
}

const char* get_st_info_bind(unsigned char st_info){
	switch(ELF64_ST_BIND(st_info)){
		case STB_LOCAL:		 return "LOCAL "; break;
		case STB_GLOBAL:	 return "GLOBAL"; break;
		case STB_WEAK:		 return "WEAK  "; break;
		case STB_GNU_UNIQUE: return "GNU_UNIQUE"; break;
		default: return "UNKOWN";
	}
}

const char* get_st_info_visibility(unsigned char st_other){
	switch(ELF64_ST_VISIBILITY(st_other)){
		case STV_DEFAULT:	return "DEFAULT  "; break;
		case STV_INTERNAL:	return "INTERNAL "; break;
		case STV_HIDDEN: 	return "HIDDEN   "; break;
		case STV_PROTECTED:	return "PROTECTED"; break;
		default: return "UNKOWN   ";
	}
}

void print_st_shndx(Elf64_Section ndx){
	switch(ndx){
		case 0: 	printf(" UND "); break;
		case 65521:	printf(" ABS "); break;
		default: 	printf("%4d ", ndx);
	}
}

// voir : siginfo-consts.h
void print_si_code(siginfo_t *siginfo)
{
	/* Values for `si_code'.  Positive values are reserved for kernel-generated signals.  */
	if(siginfo->si_code <= 0){
		switch(siginfo->si_code){
			case SI_ASYNCNL:	printf("SI_ASYNCNL : Sent by asynch name lookup completion."); break;
			case SI_DETHREAD:	printf("SI_DETHREAD : Sent by execve killing subsidiary threads."); break;
			case SI_TKILL:		printf("SI_TKILL : Sent by tkill."); break;
			case SI_SIGIO:		printf("SI_SIGIO : Sent by queued SIGIO."); break;
			case SI_ASYNCIO:	printf("SI_ASYNCIO : Sent by AIO completion."); break;
			case SI_MESGQ:		printf("SI_MESGQ : Sent by real time mesq state change."); break;
			case SI_TIMER:		printf("SI_TIMER : Sent by timer expiration."); break;
			case SI_QUEUE:		printf("SI_QUEUE : Sent by sigqueue."); break;
			case SI_USER:		printf("SI_USER : Sent by kill, sigsend."); break;
			case SI_KERNEL:		printf("SI_KERNEL : Send by kernel."); break;
			default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
		}
		return;
	}

	switch(siginfo->si_signo){
		case SIGILL:
			switch(siginfo->si_code){
				case ILL_ILLOPN: printf("ILL_ILLOPN : Illegal operand."); break;
				case ILL_ILLOPC: printf("ILL_ILLOPC : Illegal opcode."); break;
				case ILL_ILLADR: printf("ILL_ILLADR : Illegal addressing mode."); break;
				case ILL_ILLTRP: printf("ILL_ILLTRP : Illegal trap."); break;
				case ILL_PRVOPC: printf("ILL_PRVOPC : Privileged opcode."); break;
				case ILL_PRVREG: printf("ILL_PRVREG : Privileged register."); break;
				case ILL_COPROC: printf("ILL_COPROC : Coprocessor error."); break;
				case ILL_BADSTK: printf("ILL_BADSTK : Internal stack error."); break;
				case ILL_BADIADDR: printf("ILL_BADIADDR : Unimplemented instruction address."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		case SIGFPE:
			switch(siginfo->si_code){
				case FPE_INTDIV:	printf("FPE_INTDIV : Integer divide by zero."); break;
				case FPE_INTOVF:	printf("FPE_INTOVF : Integer overflow."); break;
				case FPE_FLTDIV:	printf("FPE_FLTDIV : Floating point divide by zero."); break;
				case FPE_FLTOVF:	printf("FPE_FLTOVF : Floating point overflow."); break;
				case FPE_FLTUND:	printf("FPE_FLTUND : Floating point underflow."); break;
				case FPE_FLTRES:	printf("FPE_FLTRES : Floating point inexact result."); break;
				case FPE_FLTINV:	printf("FPE_FLTINV : Floating point invalid operation."); break;
				case FPE_FLTSUB:	printf("FPE_FLTSUB : Subscript out of range."); break;
				case FPE_FLTUNK:	printf("FPE_FLTUNK : Undiagnosed floating-point exception."); break;
				case FPE_CONDTRAP:	printf("FPE_CONDTRAP : Trap on condition."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		case SIGSEGV:
			switch(siginfo->si_code){
				case SEGV_MAPERR:	printf("SEGV_MAPERR : Address not mapped to object."); break;
				case SEGV_ACCERR:	printf("SEGV_ACCERR : Invalid permissions for mapped object."); break;
				case SEGV_BNDERR:	printf("SEGV_BNDERR : Bounds checking failure."); break;
				case SEGV_PKUERR:	printf("SEGV_PKUERR : Protection key checking failure."); break;
				case SEGV_ACCADI:	printf("SEGV_ACCADI : ADI not enabled for mapped object."); break;
				case SEGV_ADIDERR:	printf("SEGV_ADIDERR : Disrupting MCD error."); break;
				case SEGV_ADIPERR:	printf("SEGV_ADIPERR : Precise MCD exception."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		case SIGBUS:
			switch(siginfo->si_code){
				case BUS_ADRALN:	printf("BUS_ADRALN : Invalid address alignment."); break;
				case BUS_ADRERR:	printf("BUS_ADRERR : Non-existant physical address."); break;
				case BUS_OBJERR:	printf("BUS_OBJERR : Object specific hardware error."); break;
				case BUS_MCEERR_AR:	printf("BUS_MCEERR_AR : Hardware memory error: action required."); break;
				case BUS_MCEERR_AO:	printf("BUS_MCEERR_AO : ardware memory error: action optional."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		// si_code for SIGTRAP undefined (?)
		/*
		case SIGTRAP:
			switch(siginfo->si_code){
				case TRAP_BRKPT:	printf("TRAP_BRKPT : Process breakpoint."); break;
				case TRAP_TRACE:	printf("TRAP_TRACE : Process trace trap."); break;
				case TRAP_BRANCH:	printf("TRAP_BRANCH : Process taken branch trap."); break;
				case TRAP_HWBKPT:	printf("TRAP_HWBKPT : Hardware breakpoint/watchpoint."); break;
				case TRAP_UNK:		printf("TRAP_UNK : Undiagnosed trap."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		*/
		case SIGCHLD:
			switch(siginfo->si_code){
				case CLD_EXITED:	printf("CLD_EXITED : Child has exited."); break;
				case CLD_KILLED:	printf("CLD_KILLED : Child was killed."); break;
				case CLD_DUMPED:	printf("CLD_DUMPED : Child terminated abnormally."); break;
				case CLD_TRAPPED:	printf("CLD_TRAPPED : Traced child has trapped."); break;
				case CLD_STOPPED:	printf("CLD_STOPPED : Child has stopped."); break;
				case CLD_CONTINUED:	printf("CLD_CONTINUED : Stopped child has continued."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		case SIGPOLL:
			switch(siginfo->si_code){
				case POLL_IN:	printf("POLL_IN : Data input available."); break;
				case POLL_OUT:	printf("POLL_OUT : Output buffers available."); break;
				case POLL_MSG:	printf("POLL_MSG : Input message available."); break;
				case POLL_ERR:	printf("POLL_ERR : I/O error."); break;
				case POLL_PRI:	printf("POLL_PRI : High priority input available."); break;
				case POLL_HUP:	printf("POLL_HUP : Device disconnected."); break;
				default: printf("-- siginfo.si_code (%d) UNKNOWN", siginfo->si_code);
			}
			break;
		default: printf("-- siginfo.si_signo (%d) UNKNOWN", siginfo->si_signo);
	}
}

