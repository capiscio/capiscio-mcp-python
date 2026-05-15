"""
Binary lifecycle management for capiscio-mcp.

Handles:
- Platform detection
- Binary download from GitHub releases
- Process supervision for embedded mode
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
import stat
import subprocess
from pathlib import Path
from typing import Optional, Tuple

import time

import requests

from capiscio_mcp._core.version import (
    CORE_MIN_VERSION,
    BINARY_NAME,
    GITHUB_REPO,
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
    """Get the directory where binaries are cached.
    
    Uses ~/.capiscio/bin/ to share cache with capiscio-sdk-python.
    """
    cache_dir = Path.home() / ".capiscio" / "bin"
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


def _fetch_expected_checksum(version: str, filename: str) -> Optional[str]:
    """Fetch the expected SHA-256 checksum from the release checksums.txt."""
    url = f"https://github.com/{GITHUB_REPO}/releases/download/v{version}/checksums.txt"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            checksum, raw_name = parts
            checksum = checksum.lower()
            # Validate SHA-256 hex format
            if len(checksum) != 64 or not all(
                c in "0123456789abcdef" for c in checksum
            ):
                continue
            # Normalize: strip leading '*' (binary mode) and path components
            entry_name = Path(raw_name.lstrip("*")).name
            if entry_name == Path(filename).name:
                return checksum
        logger.warning("Binary %s not found in checksums.txt", filename)
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("Could not fetch checksums.txt: %s", e)
        return None


def _verify_checksum(file_path: Path, expected_hash: str) -> bool:
    """Verify SHA-256 checksum of a downloaded file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    actual = sha256.hexdigest()
    if actual != expected_hash:
        logger.error(
            "Checksum mismatch: expected %s, got %s", expected_hash, actual
        )
        return False
    return True


def download_binary(version: Optional[str] = None) -> Path:
    """
    Download the capiscio-core binary for the current platform.
    
    Args:
        version: Core version to download (default: CORE_MIN_VERSION)
        
    Returns:
        Path to the downloaded binary
        
    Raises:
        CoreConnectionError: If download or checksum verification fails
    """
    version = version or CORE_MIN_VERSION
    target_path = get_binary_path(version)
    
    if target_path.exists():
        logger.debug(f"Binary already exists at {target_path}")
        return target_path
    
    os_name, arch_name = get_platform_info()
    url = get_download_url(version, os_name, arch_name)
    
    logger.info(
        f"capiscio-core v{version} not found. "
        f"Downloading for {os_name}/{arch_name}..."
    )
    
    # Ensure directory exists
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            with requests.get(url, stream=True, timeout=60) as response:
                response.raise_for_status()
                
                # Write binary
                with open(target_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            # Verify checksum BEFORE making executable
            require_checksum = os.environ.get(
                "CAPISCIO_REQUIRE_CHECKSUM", ""
            ).lower() in ("1", "true", "yes")
            expected_hash = _fetch_expected_checksum(version, target_path.name)
            if expected_hash is not None:
                if not _verify_checksum(target_path, expected_hash):
                    target_path.unlink()
                    raise CoreConnectionError(
                        f"Binary integrity check failed for {target_path.name}. "
                        "The downloaded file does not match the published checksum. "
                        "This may indicate a tampered or corrupted download."
                    )
                logger.info("Checksum verified for %s", target_path.name)
            elif require_checksum:
                target_path.unlink()
                raise CoreConnectionError(
                    f"Checksum verification required (CAPISCIO_REQUIRE_CHECKSUM=true) "
                    f"but checksums.txt is not available for v{version}. "
                    "Cannot verify binary integrity."
                )
            else:
                logger.warning(
                    "Could not verify binary integrity (checksums.txt not available). "
                    "Set CAPISCIO_REQUIRE_CHECKSUM=true to enforce verification."
                )

            # Make executable only after checksum passes (Unix)
            if os_name != "windows":
                st = os.stat(target_path)
                os.chmod(target_path, st.st_mode | stat.S_IEXEC)
            
            logger.info(f"Installed capiscio-core v{version} at {target_path}")
            return target_path
            
        except requests.exceptions.HTTPError as e:
            if target_path.exists():
                target_path.unlink()
            # Fail fast on client errors (4xx) — not transient
            if e.response is not None and 400 <= e.response.status_code < 500:
                raise CoreConnectionError(
                    f"Failed to download binary from {url}: {e}"
                ) from e
            if attempt < max_attempts:
                delay = 2 ** (attempt - 1)
                logger.warning(
                    f"Download attempt {attempt}/{max_attempts} failed: {e}. "
                    f"Retrying in {delay}s..."
                )
                time.sleep(delay)
            else:
                raise CoreConnectionError(
                    f"Failed to download binary from {url} "
                    f"after {max_attempts} attempts: {e}"
                ) from e
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, OSError) as e:
            if target_path.exists():
                target_path.unlink()
            if attempt < max_attempts:
                delay = 2 ** (attempt - 1)
                logger.warning(
                    f"Download attempt {attempt}/{max_attempts} failed: {e}. "
                    f"Retrying in {delay}s..."
                )
                time.sleep(delay)
            else:
                raise CoreConnectionError(
                    f"Failed to download binary from {url} "
                    f"after {max_attempts} attempts: {e}"
                ) from e
    # unreachable, but keeps type checker happy
    raise CoreConnectionError("Download failed")


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
    loop = asyncio.get_running_loop()
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
            
            # Capture stderr for diagnostics
            stderr_text = ""
            if self._process.stderr:
                try:
                    stderr_bytes = await self._process.stderr.read()
                    stderr_text = stderr_bytes.decode(errors="replace").strip()
                except Exception:
                    pass
            
            logger.warning(
                "capiscio-core exited with code %d%s",
                return_code,
                f": {stderr_text}" if stderr_text else "",
            )
            
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
