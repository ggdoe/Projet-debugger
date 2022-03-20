#include "tools.h"

extern struct user_regs_struct regs;

static char *str_syscall(unsigned long long orig_rax);
static void print_str_eflags(const char* format);

void print_rip(){
	size_t rip_offset;
	const char* rip_name = addr_to_func_name(regs.rip, &rip_offset);
	printf("  \033[91m%9s \033[94m%#18llx %5s\033[33m%s \033[95m(+%#lx)\n", "rip", regs.rip, "", rip_name, rip_offset);
}

void print_regs(){
	printf("  \033[91m%9s \033[94m%#18llx %5s\033[91m%s\n", "orig_rax", regs.orig_rax, "", str_syscall(regs.orig_rax));
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rax", regs.rax, regs.rax);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rbx", regs.rbx, regs.rbx);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rcx", regs.rcx, regs.rcx);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rdx", regs.rdx, regs.rdx);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rsi", regs.rsi, regs.rsi);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rdi", regs.rdi, regs.rdi);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rbp", regs.rbp, regs.rbp);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "rsp", regs.rsp, regs.rsp);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r8", regs.r8, regs.r8);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r9", regs.r9, regs.r9);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r10", regs.r10, regs.r10);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r11", regs.r11, regs.r11);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r12", regs.r12, regs.r12);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r13", regs.r13, regs.r13);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r14", regs.r14, regs.r14);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "r15", regs.r15, regs.r15);
	print_rip();
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "fs_base", regs.fs_base, regs.fs_base);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "gs_base", regs.gs_base, regs.gs_base);
	print_str_eflags("  \033[91m%9s \033[94m%#18llx \033[32m%23s\n");
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "cs", regs.cs, regs.cs);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "ss", regs.ss, regs.ss);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "ds", regs.ds, regs.ds);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "es", regs.es, regs.es);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\n", "fs", regs.fs, regs.fs);
	printf("  \033[91m%9s \033[94m%#18llx \033[96m%23llu\033[0m\n", "gs", regs.gs, regs.gs);
}

void print_str_eflags(const char* format){
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
			default: printf("UNKNOWN siginfo.si_code (%d)", siginfo->si_code);
		}
		return;
	}

	switch(siginfo->si_signo){
		case 5: printf("Breakpoint"); break;
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
				default: printf("SIGILL - UNKNOWN code (%d)", siginfo->si_code);
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
				default: printf("SIGFPE - UNKNOWN code (%d)", siginfo->si_code);
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
				default: printf("SIGSEGV - UNKNOWN code (%d)", siginfo->si_code);
			}
			break;
		case SIGBUS:
			switch(siginfo->si_code){
				case BUS_ADRALN:	printf("BUS_ADRALN : Invalid address alignment."); break;
				case BUS_ADRERR:	printf("BUS_ADRERR : Non-existant physical address."); break;
				case BUS_OBJERR:	printf("BUS_OBJERR : Object specific hardware error."); break;
				case BUS_MCEERR_AR:	printf("BUS_MCEERR_AR : Hardware memory error: action required."); break;
				case BUS_MCEERR_AO:	printf("BUS_MCEERR_AO : ardware memory error: action optional."); break;
				default: printf("SIGBUS - UNKNOWN code (%d)", siginfo->si_code);
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
				default: printf("SIGTRAP - UNKNOWN code (%d)", siginfo->si_code);
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
				default: printf("SIGCHLD - UNKNOWN code (%d)", siginfo->si_code);
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
				default: printf("SIGPOLL - UNKNOWN code (%d)", siginfo->si_code);
			}
			break;
		default: printf("UNKNOWN siginfo.si_signo (%d) ", siginfo->si_signo);
	}
}

char *str_syscall(unsigned long long orig_rax){
	switch(orig_rax){
		case 0: return "read (sys_read)"; break;
		case 1: return "write (sys_write)"; break;
		case 2: return "open (sys_open)"; break;
		case 3: return "close (sys_close)"; break;
		case 4: return "stat (sys_newstat)"; break;
		case 5: return "fstat (sys_newfstat)"; break;
		case 6: return "lstat (sys_newlstat)"; break;
		case 7: return "poll (sys_poll)"; break;
		case 8: return "lseek (sys_lseek)"; break;
		case 9: return "mmap (sys_mmap)"; break;
		case 10: return "mprotect (sys_mprotect)"; break;
		case 11: return "munmap (sys_munmap)"; break;
		case 12: return "brk (sys_brk)"; break;
		case 13: return "rt_sigaction (sys_rt_sigaction)"; break;
		case 14: return "rt_sigprocmask (sys_rt_sigprocmask)"; break;
		case 15: return "rt_sigreturn (stub_rt_sigreturn)"; break;
		case 16: return "ioctl (sys_ioctl)"; break;
		case 17: return "pread64 (sys_pread64)"; break;
		case 18: return "pwrite64 (sys_pwrite64)"; break;
		case 19: return "readv (sys_readv)"; break;
		case 20: return "writev (sys_writev)"; break;
		case 21: return "access (sys_access)"; break;
		case 22: return "pipe (sys_pipe)"; break;
		case 23: return "select (sys_select)"; break;
		case 24: return "sched_yield (sys_sched_yield)"; break;
		case 25: return "mremap (sys_mremap)"; break;
		case 26: return "msync (sys_msync)"; break;
		case 27: return "mincore (sys_mincore)"; break;
		case 28: return "madvise (sys_madvise)"; break;
		case 29: return "shmget (sys_shmget)"; break;
		case 30: return "shmat (sys_shmat)"; break;
		case 31: return "shmctl (sys_shmctl)"; break;
		case 32: return "dup (sys_dup)"; break;
		case 33: return "dup2 (sys_dup2)"; break;
		case 34: return "pause (sys_pause)"; break;
		case 35: return "nanosleep (sys_nanosleep)"; break;
		case 36: return "getitimer (sys_getitimer)"; break;
		case 37: return "alarm (sys_alarm)"; break;
		case 38: return "setitimer (sys_setitimer)"; break;
		case 39: return "getpid (sys_getpid)"; break;
		case 40: return "sendfile (sys_sendfile64)"; break;
		case 41: return "socket (sys_socket)"; break;
		case 42: return "connect (sys_connect)"; break;
		case 43: return "accept (sys_accept)"; break;
		case 44: return "sendto (sys_sendto)"; break;
		case 45: return "recvfrom (sys_recvfrom)"; break;
		case 46: return "sendmsg (sys_sendmsg)"; break;
		case 47: return "recvmsg (sys_recvmsg)"; break;
		case 48: return "shutdown (sys_shutdown)"; break;
		case 49: return "bind (sys_bind)"; break;
		case 50: return "listen (sys_listen)"; break;
		case 51: return "getsockname (sys_getsockname)"; break;
		case 52: return "getpeername (sys_getpeername)"; break;
		case 53: return "socketpair (sys_socketpair)"; break;
		case 54: return "setsockopt (sys_setsockopt)"; break;
		case 55: return "getsockopt (sys_getsockopt)"; break;
		case 56: return "clone (stub_clone)"; break;
		case 57: return "fork (stub_fork)"; break;
		case 58: return "vfork (stub_vfork)"; break;
		case 59: return "execve (stub_execve)"; break;
		case 60: return "exit (sys_exit)"; break;
		case 61: return "wait4 (sys_wait4)"; break;
		case 62: return "kill (sys_kill)"; break;
		case 63: return "uname (sys_newuname)"; break;
		case 64: return "semget (sys_semget)"; break;
		case 65: return "semop (sys_semop)"; break;
		case 66: return "semctl (sys_semctl)"; break;
		case 67: return "shmdt (sys_shmdt)"; break;
		case 68: return "msgget (sys_msgget)"; break;
		case 69: return "msgsnd (sys_msgsnd)"; break;
		case 70: return "msgrcv (sys_msgrcv)"; break;
		case 71: return "msgctl (sys_msgctl)"; break;
		case 72: return "fcntl (sys_fcntl)"; break;
		case 73: return "flock (sys_flock)"; break;
		case 74: return "fsync (sys_fsync)"; break;
		case 75: return "fdatasync (sys_fdatasync)"; break;
		case 76: return "truncate (sys_truncate)"; break;
		case 77: return "ftruncate (sys_ftruncate)"; break;
		case 78: return "getdents (sys_getdents)"; break;
		case 79: return "getcwd (sys_getcwd)"; break;
		case 80: return "chdir (sys_chdir)"; break;
		case 81: return "fchdir (sys_fchdir)"; break;
		case 82: return "rename (sys_rename)"; break;
		case 83: return "mkdir (sys_mkdir)"; break;
		case 84: return "rmdir (sys_rmdir)"; break;
		case 85: return "creat (sys_creat)"; break;
		case 86: return "link (sys_link)"; break;
		case 87: return "unlink (sys_unlink)"; break;
		case 88: return "symlink (sys_symlink)"; break;
		case 89: return "readlink (sys_readlink)"; break;
		case 90: return "chmod (sys_chmod)"; break;
		case 91: return "fchmod (sys_fchmod)"; break;
		case 92: return "chown (sys_chown)"; break;
		case 93: return "fchown (sys_fchown)"; break;
		case 94: return "lchown (sys_lchown)"; break;
		case 95: return "umask (sys_umask)"; break;
		case 96: return "gettimeofday (sys_gettimeofday)"; break;
		case 97: return "getrlimit (sys_getrlimit)"; break;
		case 98: return "getrusage (sys_getrusage)"; break;
		case 99: return "sysinfo (sys_sysinfo)"; break;
		case 100: return "times (sys_times)"; break;
		case 101: return "ptrace (sys_ptrace)"; break;
		case 102: return "getuid (sys_getuid)"; break;
		case 103: return "syslog (sys_syslog)"; break;
		case 104: return "getgid (sys_getgid)"; break;
		case 105: return "setuid (sys_setuid)"; break;
		case 106: return "setgid (sys_setgid)"; break;
		case 107: return "geteuid (sys_geteuid)"; break;
		case 108: return "getegid (sys_getegid)"; break;
		case 109: return "setpgid (sys_setpgid)"; break;
		case 110: return "getppid (sys_getppid)"; break;
		case 111: return "getpgrp (sys_getpgrp)"; break;
		case 112: return "setsid (sys_setsid)"; break;
		case 113: return "setreuid (sys_setreuid)"; break;
		case 114: return "setregid (sys_setregid)"; break;
		case 115: return "getgroups (sys_getgroups)"; break;
		case 116: return "setgroups (sys_setgroups)"; break;
		case 117: return "setresuid (sys_setresuid)"; break;
		case 118: return "getresuid (sys_getresuid)"; break;
		case 119: return "setresgid (sys_setresgid)"; break;
		case 120: return "getresgid (sys_getresgid)"; break;
		case 121: return "getpgid (sys_getpgid)"; break;
		case 122: return "setfsuid (sys_setfsuid)"; break;
		case 123: return "setfsgid (sys_setfsgid)"; break;
		case 124: return "getsid (sys_getsid)"; break;
		case 125: return "capget (sys_capget)"; break;
		case 126: return "capset (sys_capset)"; break;
		case 127: return "rt_sigpending (sys_rt_sigpending)"; break;
		case 128: return "rt_sigtimedwait (sys_rt_sigtimedwait)"; break;
		case 129: return "rt_sigqueueinfo (sys_rt_sigqueueinfo)"; break;
		case 130: return "rt_sigsuspend (sys_rt_sigsuspend)"; break;
		case 131: return "sigaltstack (sys_sigaltstack)"; break;
		case 132: return "utime (sys_utime)"; break;
		case 133: return "mknod (sys_mknod)"; break;
		case 134: return "uselib (	fs)"; break;
		case 135: return "personality (sys_personality)"; break;
		case 136: return "ustat (sys_ustat)"; break;
		case 137: return "statfs (sys_statfs)"; break;
		case 138: return "fstatfs (sys_fstatfs)"; break;
		case 139: return "sysfs (sys_sysfs)"; break;
		case 140: return "getpriority (sys_getpriority)"; break;
		case 141: return "setpriority (sys_setpriority)"; break;
		case 142: return "sched_setparam (sys_sched_setparam)"; break;
		case 143: return "sched_getparam (sys_sched_getparam)"; break;
		case 144: return "sched_setscheduler (sys_sched_setscheduler)"; break;
		case 145: return "sched_getscheduler (sys_sched_getscheduler)"; break;
		case 146: return "sched_get_priority_max (sys_sched_get_priority_max)"; break;
		case 147: return "sched_get_priority_min (sys_sched_get_priority_min)"; break;
		case 148: return "sched_rr_get_interval (sys_sched_rr_get_interval)"; break;
		case 149: return "mlock (sys_mlock)"; break;
		case 150: return "munlock (sys_munlock)"; break;
		case 151: return "mlockall (sys_mlockall)"; break;
		case 152: return "munlockall (sys_munlockall)"; break;
		case 153: return "vhangup (sys_vhangup)"; break;
		case 154: return "modify_ldt (sys_modify_ldt)"; break;
		case 155: return "pivot_root (sys_pivot_root)"; break;
		case 156: return "_sysctl (sys_sysctl)"; break;
		case 157: return "prctl (sys_prctl)"; break;
		case 158: return "arch_prctl (sys_arch_prctl)"; break;
		case 159: return "adjtimex (sys_adjtimex)"; break;
		case 160: return "setrlimit (sys_setrlimit)"; break;
		case 161: return "chroot (sys_chroot)"; break;
		case 162: return "sync (sys_sync)"; break;
		case 163: return "acct (sys_acct)"; break;
		case 164: return "settimeofday (sys_settimeofday)"; break;
		case 165: return "mount (sys_mount)"; break;
		case 166: return "umount2 (sys_umount)"; break;
		case 167: return "swapon (sys_swapon)"; break;
		case 168: return "swapoff (sys_swapoff)"; break;
		case 169: return "reboot (sys_reboot)"; break;
		case 170: return "sethostname (sys_sethostname)"; break;
		case 171: return "setdomainname (sys_setdomainname)"; break;
		case 172: return "iopl (stub_iopl)"; break;
		case 173: return "ioperm (sys_ioperm)"; break;
		case 174: return "create_module (	NOT)"; break;
		case 175: return "init_module (sys_init_module)"; break;
		case 176: return "delete_module (sys_delete_module)"; break;
		case 177: return "get_kernel_syms (	NOT)"; break;
		case 178: return "query_module (	NOT)"; break;
		case 179: return "quotactl (sys_quotactl)"; break;
		case 180: return "nfsservctl (	NOT)"; break;
		case 181: return "getpmsg (	NOT)"; break;
		case 182: return "putpmsg (	NOT)"; break;
		case 183: return "afs_syscall (	NOT)"; break;
		case 184: return "tuxcall (	NOT)"; break;
		case 185: return "security (	NOT)"; break;
		case 186: return "gettid (sys_gettid)"; break;
		case 187: return "readahead (sys_readahead)"; break;
		case 188: return "setxattr (sys_setxattr)"; break;
		case 189: return "lsetxattr (sys_lsetxattr)"; break;
		case 190: return "fsetxattr (sys_fsetxattr)"; break;
		case 191: return "getxattr (sys_getxattr)"; break;
		case 192: return "lgetxattr (sys_lgetxattr)"; break;
		case 193: return "fgetxattr (sys_fgetxattr)"; break;
		case 194: return "listxattr (sys_listxattr)"; break;
		case 195: return "llistxattr (sys_llistxattr)"; break;
		case 196: return "flistxattr (sys_flistxattr)"; break;
		case 197: return "removexattr (sys_removexattr)"; break;
		case 198: return "lremovexattr (sys_lremovexattr)"; break;
		case 199: return "fremovexattr (sys_fremovexattr)"; break;
		case 200: return "tkill (sys_tkill)"; break;
		case 201: return "time (sys_time)"; break;
		case 202: return "futex (sys_futex)"; break;
		case 203: return "sched_setaffinity (sys_sched_setaffinity)"; break;
		case 204: return "sched_getaffinity (sys_sched_getaffinity)"; break;
		case 205: return "set_thread_area (	arch)"; break;
		case 206: return "io_setup (sys_io_setup)"; break;
		case 207: return "io_destroy (sys_io_destroy)"; break;
		case 208: return "io_getevents (sys_io_getevents)"; break;
		case 209: return "io_submit (sys_io_submit)"; break;
		case 210: return "io_cancel (sys_io_cancel)"; break;
		case 211: return "get_thread_area (	arch)"; break;
		case 212: return "lookup_dcookie (sys_lookup_dcookie)"; break;
		case 213: return "epoll_create (sys_epoll_create)"; break;
		case 214: return "epoll_ctl_old (	NOT)"; break;
		case 215: return "epoll_wait_old (	NOT)"; break;
		case 216: return "remap_file_pages (sys_remap_file_pages)"; break;
		case 217: return "getdents64 (sys_getdents64)"; break;
		case 218: return "set_tid_address (sys_set_tid_address)"; break;
		case 219: return "restart_syscall (sys_restart_syscall)"; break;
		case 220: return "semtimedop (sys_semtimedop)"; break;
		case 221: return "fadvise64 (sys_fadvise64)"; break;
		case 222: return "timer_create (sys_timer_create)"; break;
		case 223: return "timer_settime (sys_timer_settime)"; break;
		case 224: return "timer_gettime (sys_timer_gettime)"; break;
		case 225: return "timer_getoverrun (sys_timer_getoverrun)"; break;
		case 226: return "timer_delete (sys_timer_delete)"; break;
		case 227: return "clock_settime (sys_clock_settime)"; break;
		case 228: return "clock_gettime (sys_clock_gettime)"; break;
		case 229: return "clock_getres (sys_clock_getres)"; break;
		case 230: return "clock_nanosleep (sys_clock_nanosleep)"; break;
		case 231: return "exit_group (sys_exit_group)"; break;
		case 232: return "epoll_wait (sys_epoll_wait)"; break;
		case 233: return "epoll_ctl (sys_epoll_ctl)"; break;
		case 234: return "tgkill (sys_tgkill)"; break;
		case 235: return "utimes (sys_utimes)"; break;
		case 236: return "vserver (	NOT)"; break;
		case 237: return "mbind (sys_mbind)"; break;
		case 238: return "set_mempolicy (sys_set_mempolicy)"; break;
		case 239: return "get_mempolicy (sys_get_mempolicy)"; break;
		case 240: return "mq_open (sys_mq_open)"; break;
		case 241: return "mq_unlink (sys_mq_unlink)"; break;
		case 242: return "mq_timedsend (sys_mq_timedsend)"; break;
		case 243: return "mq_timedreceive (sys_mq_timedreceive)"; break;
		case 244: return "mq_notify (sys_mq_notify)"; break;
		case 245: return "mq_getsetattr (sys_mq_getsetattr)"; break;
		case 246: return "kexec_load (sys_kexec_load)"; break;
		case 247: return "waitid (sys_waitid)"; break;
		case 248: return "add_key (sys_add_key)"; break;
		case 249: return "request_key (sys_request_key)"; break;
		case 250: return "keyctl (sys_keyctl)"; break;
		case 251: return "ioprio_set (sys_ioprio_set)"; break;
		case 252: return "ioprio_get (sys_ioprio_get)"; break;
		case 253: return "inotify_init (sys_inotify_init)"; break;
		case 254: return "inotify_add_watch (sys_inotify_add_watch)"; break;
		case 255: return "inotify_rm_watch (sys_inotify_rm_watch)"; break;
		case 256: return "migrate_pages (sys_migrate_pages)"; break;
		case 257: return "openat (sys_openat)"; break;
		case 258: return "mkdirat (sys_mkdirat)"; break;
		case 259: return "mknodat (sys_mknodat)"; break;
		case 260: return "fchownat (sys_fchownat)"; break;
		case 261: return "futimesat (sys_futimesat)"; break;
		case 262: return "newfstatat (sys_newfstatat)"; break;
		case 263: return "unlinkat (sys_unlinkat)"; break;
		case 264: return "renameat (sys_renameat)"; break;
		case 265: return "linkat (sys_linkat)"; break;
		case 266: return "symlinkat (sys_symlinkat)"; break;
		case 267: return "readlinkat (sys_readlinkat)"; break;
		case 268: return "fchmodat (sys_fchmodat)"; break;
		case 269: return "faccessat (sys_faccessat)"; break;
		case 270: return "pselect6 (sys_pselect6)"; break;
		case 271: return "ppoll (sys_ppoll)"; break;
		case 272: return "unshare (sys_unshare)"; break;
		case 273: return "set_robust_list (sys_set_robust_list)"; break;
		case 274: return "get_robust_list (sys_get_robust_list)"; break;
		case 275: return "splice (sys_splice)"; break;
		case 276: return "tee (sys_tee)"; break;
		case 277: return "sync_file_range (sys_sync_file_range)"; break;
		case 278: return "vmsplice (sys_vmsplice)"; break;
		case 279: return "move_pages (sys_move_pages)"; break;
		case 280: return "utimensat (sys_utimensat)"; break;
		case 281: return "epoll_pwait (sys_epoll_pwait)"; break;
		case 282: return "signalfd (sys_signalfd)"; break;
		case 283: return "timerfd_create (sys_timerfd_create)"; break;
		case 284: return "eventfd (sys_eventfd)"; break;
		case 285: return "fallocate (sys_fallocate)"; break;
		case 286: return "timerfd_settime (sys_timerfd_settime)"; break;
		case 287: return "timerfd_gettime (sys_timerfd_gettime)"; break;
		case 288: return "accept4 (sys_accept4)"; break;
		case 289: return "signalfd4 (sys_signalfd4)"; break;
		case 290: return "eventfd2 (sys_eventfd2)"; break;
		case 291: return "epoll_create1 (sys_epoll_create1)"; break;
		case 292: return "dup3 (sys_dup3)"; break;
		case 293: return "pipe2 (sys_pipe2)"; break;
		case 294: return "inotify_init1 (sys_inotify_init1)"; break;
		case 295: return "preadv (sys_preadv)"; break;
		case 296: return "pwritev (sys_pwritev)"; break;
		case 297: return "rt_tgsigqueueinfo (sys_rt_tgsigqueueinfo)"; break;
		case 298: return "perf_event_open (sys_perf_event_open)"; break;
		case 299: return "recvmmsg (sys_recvmmsg)"; break;
		case 300: return "fanotify_init (sys_fanotify_init)"; break;
		case 301: return "fanotify_mark (sys_fanotify_mark)"; break;
		case 302: return "prlimit64 (sys_prlimit64)"; break;
		case 303: return "name_to_handle_at (sys_name_to_handle_at)"; break;
		case 304: return "open_by_handle_at (sys_open_by_handle_at)"; break;
		case 305: return "clock_adjtime (sys_clock_adjtime)"; break;
		case 306: return "syncfs (sys_syncfs)"; break;
		case 307: return "sendmmsg (sys_sendmmsg)"; break;
		case 308: return "setns (sys_setns)"; break;
		case 309: return "getcpu (sys_getcpu)"; break;
		case 310: return "process_vm_readv (sys_process_vm_readv)"; break;
		case 311: return "process_vm_writev (sys_process_vm_writev)"; break;
		case 312: return "kcmp (sys_kcmp)"; break;
		case 313: return "finit_module (sys_finit_module)"; break;
		default: return "Not a syscall"; break;
	}
}
