"""
Binary lifecycle management for capiscio-mcp.

Handles:
- Platform detection
- Binary download from GitHub releases
- Process supervision for embedded mode
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import stat
import subprocess
from pathlib import Path
from typing import Optional, Tuple

import requests
from platformdirs import user_cache_dir

from capiscio_mcp._core.version import (
    CORE_MIN_VERSION,
    BINARY_NAME,
    get_download_url,
)
from capiscio_mcp.errors import CoreConnectionError

logger = logging.getLogger(__name__)


# Custom exception for binary-related errors
class BinaryNotFoundError(CoreConnectionError):
    """Raised when the capiscio-core binary cannot be found or downloaded."""
    pass


def get_platform_info() -> Tuple[str, str]:
    """
    Determine the OS and architecture.
    
    Returns:
        Tuple of (os_name, arch_name)
        
    Raises:
        RuntimeError: If platform is unsupported
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize OS
    if system == "darwin":
        os_name = "darwin"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "windows"
    else:
        raise RuntimeError(f"Unsupported operating system: {system}")

    # Normalize Architecture
    if machine in ("x86_64", "amd64"):
        arch_name = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch_name = "arm64"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    return os_name, arch_name


def get_cache_dir() -> Path:
    """Get the directory where binaries are cached."""
    cache_dir = Path(user_cache_dir("capiscio-mcp", "capiscio")) / "bin"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_binary_path(version: Optional[str] = None) -> Path:
    """
    Get the full path to the binary for a specific version.
    
    Args:
        version: Core version (default: CORE_MIN_VERSION)
        
    Returns:
        Path to the binary
    """
    version = version or CORE_MIN_VERSION
    os_name, arch_name = get_platform_info()
    ext = ".exe" if os_name == "windows" else ""
    filename = f"{BINARY_NAME}-{os_name}-{arch_name}{ext}"
    return get_cache_dir() / version / filename


def download_binary(version: Optional[str] = None) -> Path:
    """
    Download the capiscio-core binary for the current platform.
    
    Args:
        version: Core version to download (default: CORE_MIN_VERSION)
        
    Returns:
        Path to the downloaded binary
        
    Raises:
        CoreConnectionError: If download fails
    """
    version = version or CORE_MIN_VERSION
    target_path = get_binary_path(version)
    
    if target_path.exists():
        logger.debug(f"Binary already exists at {target_path}")
        return target_path
    
    os_name, arch_name = get_platform_info()
    url = get_download_url(version, os_name, arch_name)
    
    logger.info(f"Downloading capiscio-core v{version} for {os_name}/{arch_name}...")
    
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        # Ensure directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write binary
        with open(target_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Make executable (Unix)
        if os_name != "windows":
            st = os.stat(target_path)
            os.chmod(target_path, st.st_mode | stat.S_IEXEC)
        
        logger.info(f"Successfully installed capiscio-core v{version}")
        return target_path
        
    except requests.exceptions.RequestException as e:
        if target_path.exists():
            target_path.unlink()
        raise CoreConnectionError(f"Failed to download binary from {url}: {e}") from e
    except Exception as e:
        if target_path.exists():
            target_path.unlink()
        raise CoreConnectionError(f"Failed to install binary: {e}") from e


async def ensure_binary(version: Optional[str] = None) -> Path:
    """
    Ensure the capiscio-core binary is available (async wrapper).
    
    Downloads if not present, unless CAPISCIO_BINARY_PATH is set.
    
    Environment Variables:
        CAPISCIO_BINARY_PATH: Path to a local binary (skips download)
        CAPISCIO_BINARY: Alternative name for CAPISCIO_BINARY_PATH
        
    Args:
        version: Core version (default: CORE_MIN_VERSION)
        
    Returns:
        Path to the binary
    """
    # Check for local binary override (for CI/development)
    local_binary = os.environ.get("CAPISCIO_BINARY_PATH") or os.environ.get("CAPISCIO_BINARY")
    if local_binary:
        binary_path = Path(local_binary)
        if binary_path.exists():
            logger.info(f"Using local binary from CAPISCIO_BINARY_PATH: {binary_path}")
            return binary_path
        else:
            logger.warning(f"CAPISCIO_BINARY_PATH set but file not found: {binary_path}")
    
    # Run download in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, download_binary, version)


async def start_core_process(
    binary_path: Path,
    port: int,
    log_format: str = "json",
) -> asyncio.subprocess.Process:
    """
    Start the capiscio-core gRPC server process.
    
    Args:
        binary_path: Path to the binary
        port: Port to listen on
        log_format: Log format (json or text)
        
    Returns:
        The subprocess.Process object
        
    Raises:
        CoreConnectionError: If process fails to start
    """
    cmd = [
        str(binary_path),
        "rpc",
        "--address", f"localhost:{port}",
    ]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        logger.debug(f"Started capiscio-core process (PID: {process.pid}) on port {port}")
        return process
        
    except Exception as e:
        raise CoreConnectionError(f"Failed to start capiscio-core: {e}") from e


class ProcessSupervisor:
    """
    Supervises an embedded capiscio-core process.
    
    Handles:
    - Process startup and shutdown
    - Automatic restart on crash
    - Graceful termination
    """
    
    def __init__(
        self,
        binary_path: Path,
        port: int,
        max_restarts: int = 3,
        restart_delay: float = 1.0,
    ):
        self.binary_path = binary_path
        self.port = port
        self.max_restarts = max_restarts
        self.restart_delay = restart_delay
        
        self._process: Optional[asyncio.subprocess.Process] = None
        self._restart_count = 0
        self._running = False
        self._supervisor_task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the supervised process."""
        self._running = True
        self._restart_count = 0
        self._process = await start_core_process(self.binary_path, self.port)
        self._supervisor_task = asyncio.create_task(self._supervise())
    
    async def stop(self) -> None:
        """Stop the supervised process gracefully."""
        self._running = False
        
        if self._supervisor_task:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                pass
        
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            self._process = None
    
    async def _supervise(self) -> None:
        """Supervision loop - restart on unexpected exit."""
        while self._running:
            if self._process is None:
                break
            
            return_code = await self._process.wait()
            
            if not self._running:
                break  # Intentional shutdown
            
            logger.warning(f"capiscio-core exited with code {return_code}")
            
            if self._restart_count >= self.max_restarts:
                logger.error(f"Max restarts ({self.max_restarts}) exceeded")
                self._running = False
                break
            
            self._restart_count += 1
            logger.info(f"Restarting capiscio-core (attempt {self._restart_count})")
            
            await asyncio.sleep(self.restart_delay)
            self._process = await start_core_process(self.binary_path, self.port)
    
    @property
    def is_running(self) -> bool:
        """Check if the process is running."""
        return self._process is not None and self._process.returncode is None
