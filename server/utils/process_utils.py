"""
Process Utilities
=================

Shared utilities for process management across the codebase.
Includes Windows Job Object support for reliable process tree termination.
"""

import logging
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Literal

import psutil

logger = logging.getLogger(__name__)

# Windows-specific imports for Job Objects
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    # Windows API constants
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9

    # Structure definitions for Job Object configuration
    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    # Load kernel32 functions
    kernel32 = ctypes.windll.kernel32

    def _create_job_object() -> int | None:
        """Create a Windows Job Object configured to kill all processes on close.

        Returns:
            Job handle (int) on success, None on failure.
        """
        try:
            # Create unnamed job object
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                logger.warning("Failed to create Job Object: %s", ctypes.get_last_error())
                return None

            # Configure job to kill all processes when handle is closed
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

            success = kernel32.SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not success:
                logger.warning(
                    "Failed to configure Job Object: %s", ctypes.get_last_error()
                )
                kernel32.CloseHandle(handle)
                return None

            logger.debug("Created Job Object with handle %d", handle)
            return handle

        except Exception as e:
            logger.warning("Exception creating Job Object: %s", e)
            return None

    def _assign_process_to_job(job_handle: int, process_handle: int) -> bool:
        """Assign a process to a Job Object.

        Args:
            job_handle: Handle to the Job Object
            process_handle: Handle to the process (from proc._handle on Windows)

        Returns:
            True if assignment succeeded, False otherwise.
        """
        try:
            success = kernel32.AssignProcessToJobObject(job_handle, process_handle)
            if not success:
                error = ctypes.get_last_error()
                # Error 5 = Access Denied (process may already be in a job)
                # Error 6 = Invalid Handle
                logger.debug(
                    "Failed to assign process to Job Object: error %d", error
                )
                return False
            logger.debug(
                "Assigned process handle %d to Job Object %d",
                process_handle, job_handle
            )
            return True
        except Exception as e:
            logger.warning("Exception assigning process to Job Object: %s", e)
            return False

    def _close_job_object(job_handle: int) -> None:
        """Close a Job Object handle, terminating all processes in the job.

        Args:
            job_handle: Handle to the Job Object to close.
        """
        try:
            kernel32.CloseHandle(job_handle)
            logger.debug("Closed Job Object handle %d", job_handle)
        except Exception as e:
            logger.warning("Exception closing Job Object: %s", e)


@dataclass
class JobProcess:
    """A subprocess wrapped with a Windows Job Object for reliable cleanup.

    On Windows, the job_handle ensures ALL child processes (including grandchildren
    like MCP servers) are terminated when the job is closed.

    On non-Windows platforms, job_handle is None and cleanup uses psutil.
    """

    proc: subprocess.Popen
    job_handle: int | None = None

    def kill_tree(self, timeout: float = 5.0) -> "KillResult":
        """Kill this process and all its children.

        On Windows with a valid job_handle, closes the job to terminate all
        processes atomically. Falls back to psutil-based cleanup otherwise.
        """
        if sys.platform == "win32" and self.job_handle is not None:
            return kill_job_process_tree(self.proc, self.job_handle, timeout)
        return kill_process_tree(self.proc, timeout)


@dataclass
class KillResult:
    """Result of a process tree kill operation.

    Attributes:
        status: "success" if all processes terminated, "partial" if some required
            force-kill, "failure" if parent couldn't be killed
        parent_pid: PID of the parent process
        children_found: Number of child processes found
        children_terminated: Number of children that terminated gracefully
        children_killed: Number of children that required SIGKILL
        parent_forcekilled: Whether the parent required SIGKILL
        job_closed: Whether a Windows Job Object was closed (Windows only)
    """

    status: Literal["success", "partial", "failure"]
    parent_pid: int
    children_found: int = 0
    children_terminated: int = 0
    children_killed: int = 0
    parent_forcekilled: bool = False
    job_closed: bool = False


def spawn_with_job(
    cmd: list[str],
    **popen_kwargs: Any,
) -> JobProcess:
    """Spawn a subprocess wrapped in a Windows Job Object.

    On Windows, creates a Job Object configured to kill all processes when closed.
    The subprocess and all its descendants (including MCP servers, browser instances,
    etc.) will be terminated when the job handle is closed.

    On non-Windows platforms, simply spawns the subprocess without a job.

    Args:
        cmd: Command and arguments to execute.
        **popen_kwargs: Additional arguments passed to subprocess.Popen.

    Returns:
        JobProcess containing the Popen object and optional job handle.

    Example:
        jp = spawn_with_job(["python", "agent.py"], cwd="/path/to/project")
        # ... later ...
        jp.kill_tree()  # Kills agent AND all MCP servers it spawned
    """
    job_handle = None

    if sys.platform == "win32":
        # Create job object BEFORE spawning process
        job_handle = _create_job_object()

        # Ensure CREATE_NO_WINDOW is set (don't override other flags)
        existing_flags = popen_kwargs.get("creationflags", 0)
        popen_kwargs["creationflags"] = existing_flags | subprocess.CREATE_NO_WINDOW

    # Spawn the subprocess
    proc = subprocess.Popen(cmd, **popen_kwargs)

    if sys.platform == "win32" and job_handle is not None:
        # Assign process to job object
        # On Windows, proc._handle is the native process handle
        if hasattr(proc, "_handle") and proc._handle:
            if not _assign_process_to_job(job_handle, proc._handle):
                # Assignment failed - close job and continue without it
                logger.warning(
                    "Could not assign PID %d to Job Object, falling back to psutil cleanup",
                    proc.pid,
                )
                _close_job_object(job_handle)
                job_handle = None
        else:
            logger.warning("Process has no _handle attribute, Job Object not used")
            _close_job_object(job_handle)
            job_handle = None

    logger.debug(
        "Spawned process PID %d with job_handle=%s",
        proc.pid, job_handle
    )

    return JobProcess(proc=proc, job_handle=job_handle)


def kill_job_process_tree(
    proc: subprocess.Popen,
    job_handle: int,
    timeout: float = 5.0,
) -> KillResult:
    """Kill a process tree using a Windows Job Object.

    Closes the job handle, which atomically terminates ALL processes in the job
    including grandchildren that may have been orphaned.

    Args:
        proc: The subprocess.Popen object
        job_handle: Windows Job Object handle
        timeout: Seconds to wait for process to exit after closing job

    Returns:
        KillResult with status and statistics.
    """
    result = KillResult(status="success", parent_pid=proc.pid, job_closed=True)

    try:
        # Count children before closing job (for statistics)
        try:
            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
            result.children_found = len(children)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        logger.debug(
            "Closing Job Object %d to kill PID %d and %d children",
            job_handle, proc.pid, result.children_found
        )

        # Close job - this terminates all processes in the job
        _close_job_object(job_handle)

        # Wait for main process to exit
        try:
            proc.wait(timeout=timeout)
            result.children_terminated = result.children_found
            logger.debug("Process tree terminated via Job Object close")
        except subprocess.TimeoutExpired:
            # Job close should have killed everything, but process might be stuck
            logger.warning(
                "Process PID %d did not exit after Job Object close, force-killing",
                proc.pid
            )
            proc.kill()
            proc.wait()
            result.parent_forcekilled = True
            result.status = "partial"

    except Exception as e:
        logger.warning("Error during Job Object cleanup: %s", e)
        # Fall back to regular kill
        result.job_closed = False
        return kill_process_tree(proc, timeout)

    return result


def kill_process_tree(proc: subprocess.Popen, timeout: float = 5.0) -> KillResult:
    """Kill a process and all its child processes using psutil.

    On Windows, subprocess.terminate() only kills the immediate process, leaving
    orphaned child processes (e.g., spawned browser instances, coding/testing agents).
    This function uses psutil to kill the entire process tree.

    NOTE: For more reliable cleanup on Windows, use spawn_with_job() and JobProcess.
    This function is the fallback when Job Objects aren't available.

    Args:
        proc: The subprocess.Popen object to kill
        timeout: Seconds to wait for graceful termination before force-killing

    Returns:
        KillResult with status and statistics about the termination
    """
    result = KillResult(status="success", parent_pid=proc.pid)

    try:
        parent = psutil.Process(proc.pid)
        # Get all children recursively before terminating
        children = parent.children(recursive=True)
        result.children_found = len(children)

        logger.debug(
            "Killing process tree: PID %d with %d children",
            proc.pid, len(children)
        )

        # Terminate children first (graceful)
        for child in children:
            try:
                logger.debug("Terminating child PID %d (%s)", child.pid, child.name())
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # NoSuchProcess: already dead
                # AccessDenied: Windows can raise this for system processes or already-exited processes
                logger.debug("Child PID %d already gone or inaccessible: %s", child.pid, e)

        # Wait for children to terminate
        gone, still_alive = psutil.wait_procs(children, timeout=timeout)
        result.children_terminated = len(gone)

        logger.debug(
            "Children after graceful wait: %d terminated, %d still alive",
            len(gone), len(still_alive)
        )

        # Force kill any remaining children
        for child in still_alive:
            try:
                logger.debug("Force-killing child PID %d", child.pid)
                child.kill()
                result.children_killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.debug("Child PID %d gone during force-kill: %s", child.pid, e)

        if result.children_killed > 0:
            result.status = "partial"

        # Now terminate the parent
        logger.debug("Terminating parent PID %d", proc.pid)
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
            logger.debug("Parent PID %d terminated gracefully", proc.pid)
        except subprocess.TimeoutExpired:
            logger.debug("Parent PID %d did not terminate, force-killing", proc.pid)
            proc.kill()
            proc.wait()
            result.parent_forcekilled = True
            result.status = "partial"

        logger.debug(
            "Process tree kill complete: status=%s, children=%d (terminated=%d, killed=%d)",
            result.status, result.children_found,
            result.children_terminated, result.children_killed
        )

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        # NoSuchProcess: Process already dead
        # AccessDenied: Windows can raise this for protected/system processes
        # In either case, just ensure cleanup
        logger.debug("Parent PID %d inaccessible (%s), attempting direct cleanup", proc.pid, e)
        try:
            proc.terminate()
            proc.wait(timeout=1)
            logger.debug("Direct termination of PID %d succeeded", proc.pid)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
                logger.debug("Direct force-kill of PID %d succeeded", proc.pid)
            except OSError as kill_error:
                logger.debug("Direct force-kill of PID %d failed: %s", proc.pid, kill_error)
                result.status = "failure"

    return result
