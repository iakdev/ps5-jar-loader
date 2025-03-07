package org.ps5jb.client.payloads;

import org.ps5jb.client.utils.init.SdkInit;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.kernel.KernelAccessorIPv6;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.lib.LibKernel;

import java.io.*;

public class Elfloader implements Runnable {
    private static final int OFF_EHDR_TYPE  = 0x10;
    private static final int OFF_EHDR_ENTRY = 0x18;
    private static final int OFF_EHDR_PHOFF = 0x20;
    private static final int OFF_EHDR_SHOFF = 0x28;
    private static final int OFF_EHDR_PHNUM = 0x38;
    private static final int OFF_EHDR_SHNUM = 0x3c;

    private static final int OFF_PHDR_TYPE   = 0x00;
    private static final int OFF_PHDR_FLAGS  = 0x04;
    private static final int OFF_PHDR_OFFSET = 0x08;
    private static final int OFF_PHDR_VADDR  = 0x10;
    private static final int OFF_PHDR_FILESZ = 0x20;
    private static final int OFF_PHDR_MEMSZ  = 0x28;

    private static final int OFF_SHDR_TYPE   = 0x04;
    private static final int OFF_SHDR_OFFSET = 0x18;
    private static final int OFF_SHDR_SIZE   = 0x20;

    private static final int OFF_RELA_OFFSET = 0x00;
    private static final int OFF_RELA_INFO   = 0x08;
    private static final int OFF_RELA_ADDEND = 0x10;

    private static final int SIZE_PHDR = 0x38;
    private static final int SIZE_EHDR = 0x40;
    private static final int SIZE_SHDR = 0x40;
    private static final int SIZE_RELA = 0x18;

    private static final int ET_EXEC = 2;
    private static final int ET_DYN  = 3;

    private static final int PT_LOAD    = 0x01;
    private static final int PT_DYNAMIC = 0x02;

    private static final int SHT_RELA = 4;

    private static final int R_X86_64_RELATIVE = 8;

    private static final int PF_X = 0x1;
    private static final int PF_W = 0x2;
    private static final int PF_R = 0x4;

    private static final int PROT_NONE  = 0x0;
    private static final int PROT_READ  = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int PROT_EXEC  = 0x4;

    private static final int MAP_SHARED    = 0x1;
    private static final int MAP_PRIVATE   = 0x2;
    private static final int MAP_FIXED     = 0x10;
    private static final int MAP_ANONYMOUS = 0x1000;

    private static Pointer arg_addr;

    private KernelPointer qaFlags;
    private KernelPointer secFlags;
    private KernelPointer utokenFlags;
    private KernelPointer targetId;

    private SdkInit sdk;
    private LibKernel libKernel;
    private byte[] elfData = null;

    private void init() throws Exception {
        Status.println("Starting init...");
        if (KernelReadWrite.getAccessor(getClass().getClassLoader()) instanceof KernelAccessorIPv6) {
            Status.println("KernelAccessorIPv6 detected");
            KernelAccessorIPv6 kernelAccessor = (KernelAccessorIPv6) KernelReadWrite.getAccessor(getClass().getClassLoader());

            Pointer payload_output_addr = Pointer.calloc(8);
            Pointer pipe_rw_fds = Pointer.calloc(8);
            Pointer kern_rw_fds = Pointer.calloc(8);

            arg_addr = Pointer.calloc(0x30);

            Status.println("Setting kern_rw_fds: masterSock=" + kernelAccessor.getMasterSock() + ", victimSock=" + kernelAccessor.getVictimSock());
            kern_rw_fds.write4(kernelAccessor.getMasterSock());
            kern_rw_fds.inc(4).write4(kernelAccessor.getVictimSock());

            Status.println("Setting pipe_rw_fds: readFd=" + kernelAccessor.getPipeReadFd() + ", writeFd=" + kernelAccessor.getPipeWriteFd());
            pipe_rw_fds.write4(kernelAccessor.getPipeReadFd());
            pipe_rw_fds.inc(4).write4(kernelAccessor.getPipeWriteFd());

            Status.println("Writing arg_addr values...");
            arg_addr.write8(libKernel.addrOf("sceKernelDlsym").addr());
            arg_addr.inc(0x08).write8(pipe_rw_fds.addr());
            arg_addr.inc(0x10).write8(kern_rw_fds.addr());
            arg_addr.inc(0x28).write8(payload_output_addr.addr());

            try {
                Status.println("Trying to set pipeAddr=" + kernelAccessor.getPipeAddr().addr() + ", kernelBase=" + sdk.kernelBaseAddress);
                arg_addr.inc(0x18).write8(kernelAccessor.getPipeAddr().addr());
                arg_addr.inc(0x20).write8(sdk.kernelBaseAddress);
            } catch (Throwable t) {
                Status.println("Failed to set pipeAddr or kernelBase: " + t.getMessage());
                arg_addr.inc(0x18).write8(0);
                arg_addr.inc(0x20).write8(0);
            }
            Status.println("Init completed successfully");
        } else {
            Status.println("KernelAccessorIPv6 not found, throwing exception");
            throw new Exception("KernelAccessorIPv6 not found");
        }
    }

    @Override
    public void run() {
        this.libKernel = new LibKernel();
        this.sdk = null;
        try {
            Status.println("Starting Elfloader run...");
            File elfFile = null;

            try {
                Status.println("Initializing SDK...");
                sdk = SdkInit.init(true, true);
                Status.println("SDK initialized");
                int uid = libKernel.getuid();
                Status.println("User ID: " + uid);
                if (uid != 0) {
                    Status.println("Current user is not root. Aborting.");
                    return;
                }

                Status.println("Searching for bdj.elf on USB...");
                for (int i = 0; i < 8; i++) {
                    try {
                        File f = new File("/mnt/usb" + i + "/bdj.elf");
                        if (f.exists()) {
                            elfFile = f;
                            Status.println("Found bdj.elf on usb" + i);
                            break;
                        } else {
                            Status.println("No bdj.elf on usb" + i);
                        }
                    } catch (Exception ex) {
                        Status.println("Error searching usb" + i + ": " + ex.getMessage());
                    }
                }

                KernelPointer kbase = KernelPointer.valueOf(sdk.kernelBaseAddress, false);
                KernelOffsets o = sdk.kernelOffsets;
                Status.println("Setting kernel pointers...");
                qaFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_QA_FLAGS);
                secFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS);
                utokenFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS);
                targetId = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_TARGET_ID);

                Status.println("Original kernel values:");
                printFlags();

                Status.println("Checking need for AGC switch...");
                if (sdk.switchToAgcKernelReadWrite(true)) {
                    Status.println("Switched to AGC-based kernel r/w");
                } else {
                    Status.println("No switch to AGC needed or failed");
                }

                Status.println("Modifying kernel values...");
                int qaFlagsVal = qaFlags.read4();
                qaFlags.write4(qaFlagsVal | 0x10300);
                int secFlagsVal = secFlags.read4();
                secFlags.write4(secFlagsVal | 0x14);
                byte targetIdVal = targetId.read1();
                targetId.write1((byte) 0x82);
                byte utokenVal = utokenFlags.read1();
                utokenFlags.write1((byte) ((utokenVal | 0x01) & 0xFF));
                Status.println("New kernel values:");
                printFlags();
            } finally {
                if (sdk != null) {
                    Status.println("Restoring non-AGC kernel r/w...");
                    sdk.restoreNonAgcKernelReadWrite();
                    Status.println("Switched back to original kernel r/w");
                }
            }

            if (elfFile == null) {
                Status.println("No bdj.elf found! Aborting.");
                return;
            }

            Status.println("Reading bdj.elf...");
            this.elfData = new byte[(int) elfFile.length()];
            int read = new FileInputStream(elfFile).read(this.elfData);
            Status.println("# bytes of bdj.elf read: " + read);

            File procDumpBeforeSetup = new File(elfFile.getParentFile(), "before_setup.procdump");
            if (procDumpBeforeSetup.exists()) {
                procDumpBeforeSetup.delete();
                Status.println("Deleted existing before_setup.procdump");
            }
            Status.println("Dumping current process to " + procDumpBeforeSetup.getAbsolutePath());
            DumpCurProcUtil.dumpCurProcToFile(procDumpBeforeSetup, libKernel, sdk);
            Status.println("Before setup dump completed");

            Status.println("Initializing ELF loader...");
            init();

            File procDumpAfterSetup = new File(elfFile.getParentFile(), "after_setup.procdump");
            if (procDumpAfterSetup.exists()) {
                procDumpAfterSetup.delete();
                Status.println("Deleted existing after_setup.procdump");
            }
            Status.println("Dumping current process to " + procDumpAfterSetup.getAbsolutePath());
            DumpCurProcUtil.dumpCurProcToFile(procDumpAfterSetup, libKernel, sdk);
            Status.println("After setup dump completed");

            Status.println("Trying to run ELF...");
            runElf(this.elfData);

            File procDumpPostRun = new File(elfFile.getParentFile(), "post_run.procdump");
            if (procDumpPostRun.exists()) {
                procDumpPostRun.delete();
                Status.println("Deleted existing post_run.procdump");
            }
            Status.println("Dumping current process to " + procDumpPostRun.getAbsolutePath());
            DumpCurProcUtil.dumpCurProcToFile(procDumpPostRun, libKernel, sdk);
            Status.println("Post run dump completed");

        } catch (Exception e) {
            Status.println("Exception in run: " + e.getMessage());
            throw new RuntimeException(e);
        } finally {
            if (sdk != null) {
                Status.println("Final restore of non-AGC kernel r/w...");
                sdk.restoreNonAgcKernelReadWrite();
            }
            Status.println("Closing libKernel...");
            libKernel.closeLibrary();
            Status.println("Elfloader run finished");
        }
    }

    public void runElf(byte[] bytes) throws Exception {
        OutputStream os = new FileOutputStream("/dev/null");
        try {
            Status.println("Starting runElf with output to /dev/null");
            runElf(bytes, os);
            Status.println("runElf completed successfully");
        } finally {
            os.close();
            Status.println("Output stream closed");
        }
    }

    private long ROUND_PG(long val) {
        return (val + 0x3FFF) & 0xFFFFC000;
    }

    private static long TRUNC_PG(long val) {
        return val & 0xFFFFC000;
    }

    private static int PFLAGS(int p_flags) {
        int prot = 0;
        if ((p_flags & PF_X) == PF_X) prot |= PROT_EXEC;
        if ((p_flags & PF_W) == PF_W) prot |= PROT_WRITE;
        if ((p_flags & PF_R) == PF_R) prot |= PROT_READ;
        return prot;
    }

    private void r_relative(Pointer base_addr, Pointer rela_addr) throws Exception {
        long r_offset = rela_addr.inc(OFF_RELA_OFFSET).read8();
        long r_addend = rela_addr.inc(OFF_RELA_ADDEND).read8();
        Status.println("Applying relocation: offset=" + r_offset + ", addend=" + r_addend);
        base_addr.inc(r_offset).write8(base_addr.addr() + r_addend);
        Status.println("Relocation applied at " + base_addr.inc(r_offset).addr());
    }

    private void pt_load(Pointer elf_addr, Pointer base_addr, Pointer phdr_addr) throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_filesz = phdr_addr.inc(OFF_PHDR_FILESZ).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        Status.println("pt_load: offset=" + p_offset + ", vaddr=" + p_vaddr + ", filesz=" + p_filesz + ", memsz=" + p_memsz);
        if (p_memsz == 0) {
            Status.println("pt_load: memsz is 0, skipping");
            return;
        }
        long memsz = ROUND_PG(p_memsz);
        Pointer addr = base_addr.inc(p_vaddr);
        Status.println("Calling mmap: addr=" + addr.addr() + ", size=" + memsz);
        addr = libKernel.mmap(addr, memsz, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        Status.println("mmap returned: " + addr.addr());
        if (addr.addr() == -1) {
            Status.println("pt_load: mmap failed with -1");
            throw new Exception("pt_load: mmap returned -1");
        }
        if (p_filesz > 0) {
            Status.println("Copying " + p_filesz + " bytes from elf_addr+" + p_offset + " to " + addr.addr());
            elf_addr.inc(p_offset).copyTo(addr, 0, (int) p_filesz);
            Status.println("Copy completed");
        }
    }

    private void pt_dynamic(Pointer elf_addr, Pointer base_addr, Pointer phdr_addr) throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_filesz = phdr_addr.inc(OFF_PHDR_FILESZ).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        Status.println("pt_dynamic: offset=" + p_offset + ", vaddr=" + p_vaddr + ", filesz=" + p_filesz + ", memsz=" + p_memsz);
        if (p_memsz == 0) {
            Status.println("pt_dynamic: memsz is 0, skipping");
            return;
        }
        long memsz = ROUND_PG(p_memsz);
        Pointer addr = base_addr.inc(p_vaddr);
        Status.println("Calling mmap: addr=" + addr.addr() + ", size=" + memsz);
        addr = libKernel.mmap(addr, memsz, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        Status.println("mmap returned: " + addr.addr());
        if (addr.addr() == -1) {
            Status.println("pt_dynamic: mmap failed with -1");
            throw new Exception("pt_dynamic: mmap returned -1");
        }
        if (p_filesz > 0) {
            Status.println("Copying " + p_filesz + " bytes from elf_addr+" + p_offset + " to " + addr.addr());
            elf_addr.inc(p_offset).copyTo(addr, 0, (int) p_filesz);
            Status.println("Copy completed");
        }
        Status.println("pt_dynamic: Dynamic section loaded at " + addr.addr());
    }

    private void pt_reload(Pointer base_addr, Pointer phdr_addr) throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        int p_flags = phdr_addr.inc(OFF_PHDR_FLAGS).read4();
        Status.println("pt_reload: offset=" + p_offset + ", vaddr=" + p_vaddr + ", memsz=" + p_memsz + ", flags=" + p_flags);
        Pointer addr = base_addr.inc(p_vaddr);
        long memsz = ROUND_PG(p_memsz);
        int prot = PFLAGS(p_flags);
        if ((p_flags & PF_X) == PF_X) prot |= PROT_EXEC;
        Status.println("pt_reload: addr=" + addr.addr() + ", memsz=" + memsz + ", prot=" + prot);
        Pointer ret_addr = Pointer.calloc(8);
        Pointer data = Pointer.calloc(memsz);
        Status.println("Backing up data to temporary buffer...");
        addr.copyTo(data, 0, (int) memsz);
        Status.println("Data backup completed");
        int alias_fd = -1;
        int shm_fd = -1;
        try {
            Status.println("Creating shared memory...");
            if (libKernel.jitCreateSharedMemory(0, memsz, prot | PROT_READ | PROT_WRITE, ret_addr.addr()) == 0) {
                shm_fd = ret_addr.read4();
                Status.println("jitCreateSharedMemory succeeded, shm_fd=" + shm_fd);
            } else {
                Status.println("jitCreateSharedMemory failed");
                throw new Exception("pt_reload: jitCreateSharedMemory failed");
            }
            Status.println("Mapping shared memory...");
            if (libKernel.mmap(addr, memsz, prot, MAP_FIXED | MAP_PRIVATE, shm_fd, 0).addr() == -1) {
                Status.println("mmap for shared memory failed");
                throw new Exception("pt_reload: mmap shm failed");
            }
            Status.println("Shared memory mapped at " + addr.addr());
            Status.println("Creating alias of shared memory...");
            if (libKernel.jitCreateAliasOfSharedMemory(shm_fd, PROT_READ | PROT_WRITE, ret_addr.addr()) == 0) {
                alias_fd = ret_addr.read4();
                Status.println("jitCreateAliasOfSharedMemory succeeded, alias_fd=" + alias_fd);
            } else {
                Status.println("jitCreateAliasOfSharedMemory failed");
                throw new Exception("pt_reload: jitCreateAliasOfSharedMemory failed");
            }
            Status.println("Mapping alias...");
            addr = libKernel.mmap(Pointer.NULL, memsz, PROT_READ | PROT_WRITE, MAP_SHARED, alias_fd, 0);
            Status.println("mmap alias returned: " + addr.addr());
            if (addr.addr() == -1) {
                Status.println("mmap for alias failed");
                throw new Exception("pt_reload: mmap shm alias failed");
            }
            Status.println("Restoring data to alias...");
            addr.write(data.read((int) memsz));
            Status.println("Data restored");
            Status.println("Unmapping alias...");
            libKernel.munmap(addr, memsz);
            Status.println("Alias unmapped");
        } finally {
            ret_addr.free();
            data.free();
            if (alias_fd != -1) {
                Status.println("Closing alias_fd=" + alias_fd);
                libKernel.close(alias_fd);
            }
            if (shm_fd != -1) {
                Status.println("Closing shm_fd=" + shm_fd);
                libKernel.close(shm_fd);
            }
        }
    }

    public void runElf(byte[] elf_bytes, OutputStream os) throws Exception {
        Pointer elf_addr = Pointer.NULL;
        Pointer base_addr = Pointer.NULL;
        long base_size = 0;
        long min_vaddr = -1;
        long max_vaddr = -1;
        Status.println("Starting runElf with " + elf_bytes.length + " bytes");
        if (elf_bytes[0] != (byte) 0x7f || elf_bytes[1] != (byte) 0x45 || elf_bytes[2] != (byte) 0x4c || elf_bytes[3] != (byte) 0x46) {
            Status.println("ELF magic number invalid");
            throw new IOException("Invalid ELF file");
        }
        Status.println("ELF validity check passed");
        try {
            Status.println("Allocating memory for ELF bytes...");
            elf_addr = Pointer.calloc(elf_bytes.length);
            for (int i = 0; i < elf_bytes.length; i++) {
                elf_addr.inc(i).write1(elf_bytes[i]);
            }
            Status.println("ELF bytes written to " + elf_addr.addr());
            short e_type = elf_addr.inc(OFF_EHDR_TYPE).read2();
            long e_entry = elf_addr.inc(OFF_EHDR_ENTRY).read8();
            long e_phoff = elf_addr.inc(OFF_EHDR_PHOFF).read8();
            long e_shoff = elf_addr.inc(OFF_EHDR_SHOFF).read8();
            short e_phnum = elf_addr.inc(OFF_EHDR_PHNUM).read2();
            short e_shnum = elf_addr.inc(OFF_EHDR_SHNUM).read2();
            Status.println("ELF header: type=" + e_type + ", entry=" + e_entry + ", phoff=" + e_phoff + ", shoff=" + e_shoff + ", phnum=" + e_phnum + ", shnum=" + e_shnum);
            if (e_type == ET_DYN) {
                Status.println("ELF type is ET_DYN, base_addr set to NULL");
            } else if (e_type == ET_EXEC) {
                Status.println("ELF type is ET_EXEC, base_addr set to min_vaddr");
            }
            Status.println("Computing virtual memory region...");
            for (int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
                Status.println("PHDR " + i + ": vaddr=" + p_vaddr + ", memsz=" + p_memsz);
                if (p_vaddr < min_vaddr || min_vaddr == -1) min_vaddr = p_vaddr;
                if (max_vaddr < p_vaddr + p_memsz) max_vaddr = p_vaddr + p_memsz;
            }
            Status.println("Virtual memory region: min_vaddr=" + min_vaddr + ", max_vaddr=" + max_vaddr);
            min_vaddr = TRUNC_PG(min_vaddr);
            max_vaddr = ROUND_PG(max_vaddr);
            base_size = max_vaddr - min_vaddr;
            Status.println("Adjusted memory region: min_vaddr=" + min_vaddr + ", max_vaddr=" + max_vaddr + ", base_size=" + base_size);
            int flags = MAP_PRIVATE | MAP_ANONYMOUS;
            if (e_type == ET_DYN) {
                base_addr = Pointer.NULL;
            } else if (e_type == ET_EXEC) {
                base_addr = Pointer.valueOf(min_vaddr);
                flags |= MAP_FIXED;
            } else {
                Status.println("Unsupported ELF type: " + e_type);
                throw new IOException("Unsupported ELF file");
            }
            Status.println("Reserving address space: base_addr=" + base_addr.addr() + ", size=" + base_size);
            base_addr = libKernel.mmap(base_addr, base_size, PROT_NONE, flags, -1, 0);
            Status.println("mmap returned: " + base_addr.addr());
            if (base_addr.addr() == -1) {
                Status.println("runElf: mmap failed with -1");
                throw new Exception("runElf: mmap failed");
            }
            Status.println("Parsing program headers...");
            for (int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                int p_type = phdr_addr.inc(OFF_PHDR_TYPE).read4();
                Status.println("PHDR " + i + " type=" + p_type);
                if (p_type == PT_LOAD) {
                    Status.println("Processing PT_LOAD for PHDR " + i);
                    pt_load(elf_addr, base_addr, phdr_addr);
                    Status.println("PT_LOAD for PHDR " + i + " completed");
                } else if (p_type == PT_DYNAMIC) {
                    Status.println("Processing PT_DYNAMIC for PHDR " + i);
                    pt_dynamic(elf_addr, base_addr, phdr_addr);
                }
            }
            Status.println("Applying relocations...");
            for (int i = 0; i < e_shnum; i++) {
                Pointer shdr_addr = elf_addr.inc(e_shoff).inc(i * SIZE_SHDR);
                int sh_type = shdr_addr.inc(OFF_SHDR_TYPE).read4();
                Status.println("SHDR " + i + " type=" + sh_type);
                if (sh_type != SHT_RELA) {
                    Status.println("SHDR " + i + " is not SHT_RELA, skipping");
                    continue;
                }
                long sh_offset = shdr_addr.inc(OFF_SHDR_OFFSET).read8();
                long sh_size = shdr_addr.inc(OFF_SHDR_SIZE).read8();
                Status.println("SHDR " + i + ": offset=" + sh_offset + ", size=" + sh_size);
                int rela_count = (int) (sh_size / SIZE_RELA);
                Status.println("Processing " + rela_count + " RELA entries");
                for (int j = 0; j < rela_count; j++) {
                    Pointer rela_addr = elf_addr.inc(sh_offset).inc(SIZE_RELA * j);
                    long r_info = rela_addr.inc(OFF_RELA_INFO).read8();
                    Status.println("RELA " + j + ": info=" + r_info);
                    if (r_info == R_X86_64_RELATIVE) {
                        r_relative(base_addr, rela_addr);
                        Status.println("R_X86_64_RELATIVE applied for RELA " + j);
                    } else {
                        Status.println("Unsupported relocation type: " + r_info + ", skipping");
                    }
                }
            }
            Status.println("Setting protection bits...");
            for (int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
                long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                int p_type = phdr_addr.inc(OFF_PHDR_TYPE).read4();
                int p_flags = phdr_addr.inc(OFF_PHDR_FLAGS).read4();
                Status.println("PHDR " + i + ": type=" + p_type + ", memsz=" + p_memsz + ", vaddr=" + p_vaddr + ", flags=" + p_flags);
                if (p_type != PT_LOAD && p_type != PT_DYNAMIC || p_memsz == 0) {
                    Status.println("Skipping PHDR " + i + " (not PT_LOAD/PT_DYNAMIC or memsz=0)");
                    continue;
                }
                if ((p_flags & PF_X) == PF_X) {
                    Status.println("Processing executable segment for PHDR " + i);
                    pt_reload(base_addr, phdr_addr);
                    Status.println("Executable segment processed for PHDR " + i);
                    continue;
                }
                Pointer addr = base_addr.inc(p_vaddr);
                long memsz = ROUND_PG(p_memsz);
                int prot = PFLAGS(p_flags);
                Status.println("Calling mprotect: addr=" + addr.addr() + ", size=" + memsz + ", prot=" + prot);
                if (libKernel.mprotect(addr, memsz, prot) != 0) {
                    Status.println("mprotect failed for PHDR " + i);
                    throw new Exception("runElf: mprotect failed");
                }
                Status.println("mprotect succeeded for PHDR " + i);
            }
            if (base_addr.addr() != -1) {
                long entry_point = base_addr.inc(e_entry).addr();
                Status.println("Preparing to invoke entry point at " + entry_point + " with arg_addr=" + arg_addr.addr());
                if (entry_point <= 0) {
                    Status.println("Invalid entry point address: " + entry_point);
                    throw new Exception("Invalid entry point address");
                }
                if (arg_addr.addr() <= 0) {
                    Status.println("Invalid arg_addr: " + arg_addr.addr());
                    throw new Exception("Invalid arg_addr");
                }
                long args[] = new long[6];
                args[0] = arg_addr.addr();
                args[1] = 0;
                args[2] = 0;
                args[3] = 0;
                args[4] = 0;
                args[5] = 0;
                Status.println("Invoking entry point at " + entry_point + " with args: [" + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3] + ", " + args[4] + ", " + args[5] + "]");
                libKernel.call(base_addr.inc(e_entry), args);
                Status.println("Entry point invoked successfully. ELF execution completed");
            } else {
                Status.println("Invalid base_addr, cannot invoke entry point");
                throw new IOException("Invalid ELF file");
            }
        } finally {
            if (elf_addr.addr() != 0) {
                Status.println("Freeing elf_addr=" + elf_addr.addr());
                elf_addr.free();
            }
            if (base_addr.addr() != -1) {
                Status.println("Unmapping base_addr=" + base_addr.addr() + ", size=" + base_size);
                libKernel.munmap(base_addr, base_size);
            }
            Status.println("runElf cleanup completed");
        }
    }

    private void printFlags() {
        Status.println("  QA Flags: 0x" + Integer.toHexString(qaFlags.read4()));
        Status.println("  Security Flags: 0x" + Integer.toHexString(secFlags.read4()));
        Status.println("  Utoken Flags: 0x" + Integer.toHexString(utokenFlags.read1() & 0xFF));
        Status.println("  Target ID: 0x" + Integer.toHexString(targetId.read1() & 0xFF));
    }
}