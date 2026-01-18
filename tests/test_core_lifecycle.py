"""Tests for capiscio_mcp._core.lifecycle module."""

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from capiscio_mcp._core.lifecycle import (
    get_platform_info,
    get_binary_path,
    get_cache_dir,
    download_binary,
    ensure_binary,
    start_core_process,
    ProcessSupervisor,
    BinaryNotFoundError,
)
from capiscio_mcp._core.version import CORE_MIN_VERSION


class TestGetPlatformInfo:
    """Tests for get_platform_info function."""
    
    def test_returns_tuple(self):
        """Should return (os, arch) tuple."""
        result = get_platform_info()
        assert isinstance(result, tuple)
        assert len(result) == 2
    
    def test_os_is_valid(self):
        """OS should be one of known values."""
        os_name, _ = get_platform_info()
        assert os_name in ("linux", "darwin", "windows")
    
    def test_arch_is_valid(self):
        """Architecture should be one of known values."""
        _, arch = get_platform_info()
        assert arch in ("amd64", "arm64")
    
    @patch("platform.system")
    @patch("platform.machine")
    def test_linux_x86_64(self, mock_machine, mock_system):
        """Linux x86_64 should map correctly."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "x86_64"
        
        os_name, arch = get_platform_info()
        
        assert os_name == "linux"
        assert arch == "amd64"
    
    @patch("platform.system")
    @patch("platform.machine")
    def test_darwin_arm64(self, mock_machine, mock_system):
        """macOS ARM64 should map correctly."""
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "arm64"
        
        os_name, arch = get_platform_info()
        
        assert os_name == "darwin"
        assert arch == "arm64"
    
    @patch("platform.system")
    @patch("platform.machine")
    def test_windows_amd64(self, mock_machine, mock_system):
        """Windows AMD64 should map correctly."""
        mock_system.return_value = "Windows"
        mock_machine.return_value = "AMD64"
        
        os_name, arch = get_platform_info()
        
        assert os_name == "windows"
        assert arch == "amd64"
    
    @patch("platform.system")
    @patch("platform.machine")
    def test_linux_aarch64(self, mock_machine, mock_system):
        """Linux aarch64 should map to arm64."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "aarch64"
        
        os_name, arch = get_platform_info()
        
        assert os_name == "linux"
        assert arch == "arm64"


class TestGetCacheDir:
    """Tests for get_cache_dir function."""
    
    def test_returns_path(self):
        """Should return a Path object."""
        result = get_cache_dir()
        assert isinstance(result, Path)
    
    def test_path_exists(self):
        """Cache directory should exist after call."""
        result = get_cache_dir()
        assert result.exists()
    
    def test_path_is_directory(self):
        """Should be a directory."""
        result = get_cache_dir()
        assert result.is_dir()


class TestGetBinaryPath:
    """Tests for get_binary_path function."""
    
    def test_returns_path(self):
        """Should return a Path object."""
        result = get_binary_path()
        assert isinstance(result, Path)
    
    def test_path_contains_capiscio(self):
        """Path should contain 'capiscio'."""
        result = get_binary_path()
        assert "capiscio" in str(result).lower()
    
    def test_binary_name_contains_platform(self):
        """Binary name should contain platform info."""
        result = get_binary_path()
        binary_name = result.name
        os_name, arch_name = get_platform_info()
        
        assert os_name in binary_name
        assert arch_name in binary_name
    
    def test_path_contains_version(self):
        """Path should contain version subdirectory."""
        result = get_binary_path()
        assert CORE_MIN_VERSION in str(result)
    
    def test_custom_version(self):
        """Should use custom version in path."""
        result = get_binary_path(version="2.6.0")
        assert "2.6.0" in str(result)


class TestDownloadBinary:
    """Tests for download_binary function (sync)."""
    
    @patch("requests.get")
    @patch("capiscio_mcp._core.lifecycle.get_binary_path")
    def test_returns_existing_binary(self, mock_path, mock_get):
        """Should return existing binary without download."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "capiscio"
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            binary_path.write_bytes(b"existing binary")
            mock_path.return_value = binary_path
            
            result = download_binary()
            
            assert result == binary_path
            mock_get.assert_not_called()
    
    @patch("requests.get")
    @patch("capiscio_mcp._core.lifecycle.get_binary_path")
    def test_download_success(self, mock_path, mock_get):
        """Successful download should return binary path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "subdir" / "capiscio"
            mock_path.return_value = binary_path
            
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.iter_content = MagicMock(return_value=[b"binary", b"content"])
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response
            
            result = download_binary()
            
            assert result == binary_path
            assert binary_path.exists()
    
    @patch("requests.get")
    @patch("capiscio_mcp._core.lifecycle.get_binary_path")
    def test_download_404_error(self, mock_path, mock_get):
        """404 response should raise error."""
        import requests
        
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "subdir" / "capiscio"
            mock_path.return_value = binary_path
            
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404")
            mock_get.return_value = mock_response
            
            from capiscio_mcp.errors import CoreConnectionError
            with pytest.raises(CoreConnectionError):
                download_binary()
    
    @patch("requests.get")
    @patch("capiscio_mcp._core.lifecycle.get_binary_path")
    def test_download_sets_executable(self, mock_path, mock_get):
        """Downloaded binary should be executable on Unix."""
        if sys.platform == "win32":
            pytest.skip("Executable test not applicable on Windows")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "subdir" / "capiscio"
            mock_path.return_value = binary_path
            
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.iter_content = MagicMock(return_value=[b"#!/bin/sh\necho hello"])
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response
            
            result = download_binary()
            
            assert os.access(result, os.X_OK)


class TestEnsureBinary:
    """Tests for ensure_binary async function."""
    
    @pytest.mark.asyncio
    async def test_returns_path(self):
        """Should return path to binary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "capiscio"
            binary_path.write_bytes(b"existing binary")
            
            with patch("capiscio_mcp._core.lifecycle.download_binary", return_value=binary_path):
                result = await ensure_binary()
                assert isinstance(result, Path)
    
    @pytest.mark.asyncio
    async def test_calls_download_binary(self):
        """Should call download_binary in executor when no local override."""
        # Clear any CAPISCIO_BINARY_PATH env var to ensure download path is taken
        with patch.dict(os.environ, {}, clear=True):
            with patch("capiscio_mcp._core.lifecycle.download_binary") as mock_download:
                mock_download.return_value = Path("/tmp/capiscio")
                
                await ensure_binary()
                
                mock_download.assert_called_once()


class TestStartCoreProcess:
    """Tests for start_core_process function."""
    
    @pytest.mark.asyncio
    async def test_returns_process(self):
        """Should return subprocess.Process."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_exec.return_value = mock_process
            
            result = await start_core_process(Path("/bin/capiscio"), port=50051)
            
            assert result is mock_process
    
    @pytest.mark.asyncio
    async def test_correct_command(self):
        """Should invoke correct command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = MagicMock()
            mock_exec.return_value = mock_process
            
            await start_core_process(Path("/bin/capiscio"), port=50051)
            
            call_args = mock_exec.call_args
            cmd = call_args[0]
            
            assert "/bin/capiscio" in cmd[0]
            assert "rpc" in cmd
            assert "--address" in cmd
            assert "localhost:50051" in cmd


class TestProcessSupervisor:
    """Tests for ProcessSupervisor class."""
    
    def test_init(self):
        """Should initialize with correct attributes."""
        supervisor = ProcessSupervisor(
            binary_path=Path("/bin/capiscio"),
            port=50051,
            max_restarts=5,
        )
        
        assert supervisor.binary_path == Path("/bin/capiscio")
        assert supervisor.port == 50051
        assert supervisor.max_restarts == 5
    
    @pytest.mark.asyncio
    async def test_start(self):
        """Should start capiscio-core process."""
        supervisor = ProcessSupervisor(
            binary_path=Path("/bin/capiscio"),
            port=50051,
        )
        
        with patch("capiscio_mcp._core.lifecycle.start_core_process") as mock_start:
            mock_process = MagicMock()
            mock_process.returncode = None
            mock_process.wait = AsyncMock(return_value=0)
            mock_start.return_value = mock_process
            
            await supervisor.start()
            
            mock_start.assert_called_once_with(Path("/bin/capiscio"), 50051)
            assert supervisor._process is mock_process
    
    @pytest.mark.asyncio
    async def test_stop(self):
        """Should stop running process."""
        supervisor = ProcessSupervisor(
            binary_path=Path("/bin/capiscio"),
            port=50051,
        )
        
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.terminate = MagicMock()
        mock_process.wait = AsyncMock(return_value=0)
        mock_process.kill = MagicMock()
        
        supervisor._process = mock_process
        supervisor._running = True
        supervisor._supervisor_task = asyncio.create_task(asyncio.sleep(100))
        
        await supervisor.stop()
        
        mock_process.terminate.assert_called_once()
    
    def test_is_running_true(self):
        """is_running should return True for running process."""
        supervisor = ProcessSupervisor(
            binary_path=Path("/bin/capiscio"),
            port=50051,
        )
        
        mock_process = MagicMock()
        mock_process.returncode = None  # Still running
        
        supervisor._process = mock_process
        
        assert supervisor.is_running is True
    
    def test_is_running_false(self):
        """is_running should return False for stopped process."""
        supervisor = ProcessSupervisor(
            binary_path=Path("/bin/capiscio"),
            port=50051,
        )
        
        mock_process = MagicMock()
        mock_process.returncode = 0  # Stopped
        
        supervisor._process = mock_process
        
        assert supervisor.is_running is False
    
    def test_is_running_no_process(self):
        """is_running should return False when no process."""
        supervisor = ProcessSupervisor(
            binary_path=Path("/bin/capiscio"),
            port=50051,
        )
        
        assert supervisor.is_running is False


class TestBinaryNotFoundError:
    """Tests for BinaryNotFoundError exception."""
    
    def test_error_message(self):
        """Error should have descriptive message."""
        error = BinaryNotFoundError("Binary not found for linux/amd64")
        assert "linux" in str(error)
        assert "amd64" in str(error)
    
    def test_is_exception(self):
        """Should be a proper exception."""
        error = BinaryNotFoundError("test")
        assert isinstance(error, Exception)
        
        with pytest.raises(BinaryNotFoundError):
            raise error
    
    def test_inherits_core_connection_error(self):
        """Should inherit from CoreConnectionError."""
        from capiscio_mcp.errors import CoreConnectionError
        error = BinaryNotFoundError("test")
        assert isinstance(error, CoreConnectionError)
