# https://bugs.python.org/issue41437#msg374590
import ctypes
import threading
import contextlib

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CTRL_C_EVENT = 0
THREAD_SET_CONTEXT = 0x0010


@contextlib.contextmanager
def ctrl_cancel_async_io(file_handle):
    apc_sync_event = threading.Event()
    hthread = kernel32.OpenThread(
        THREAD_SET_CONTEXT, False, kernel32.GetCurrentThreadId()
    )
    if not hthread:
        raise ctypes.WinError(ctypes.get_last_error())

    @ctypes.WINFUNCTYPE(None, ctypes.c_void_p)
    def apc_cancel_io(ignored):
        kernel32.CancelIo(file_handle)
        apc_sync_event.set()

    @ctypes.WINFUNCTYPE(ctypes.c_uint, ctypes.c_uint)
    def ctrl_handler(ctrl_event):
        # For a Ctrl+C cancel event, queue an async procedure call
        # to the target thread that cancels pending async I/O for
        # the given file handle.
        if ctrl_event == CTRL_C_EVENT:
            kernel32.QueueUserAPC(apc_cancel_io, hthread, None)
            # Synchronize here in case the APC was queued to the
            # main thread, else apc_cancel_io might get interrupted
            # by a KeyboardInterrupt.
            apc_sync_event.wait()
        return False  # chain to next handler

    try:
        kernel32.SetConsoleCtrlHandler(ctrl_handler, True)
        yield
    finally:
        kernel32.SetConsoleCtrlHandler(ctrl_handler, False)
        kernel32.CloseHandle(hthread)


def get_win_folder():
    buffer = ctypes.create_unicode_buffer(1024)
    # https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetfolderpatha
    ctypes.windll.shell32.SHGetFolderPathW(
        None,
        26,  # APPDATA
        None,
        0,
        buffer,
    )
    return buffer.value
