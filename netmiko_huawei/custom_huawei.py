from typing import Optional, Any, Union, Sequence, Iterator, TextIO, Dict
import time
import re
import warnings
import sys
from netmiko.no_enable import NoEnable
from netmiko.base_connection import DELAY_FACTOR_DEPR_SIMPLE_MSG
from netmiko.cisco_base_connection import CiscoBaseConnection
from netmiko.exceptions import NetmikoAuthenticationException
from netmiko import log
from typing import Any, Optional, Callable, Type
from types import TracebackType
import time
import re
import os
import hashlib
import io
import itertools
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    ConfigInvalidException,
    ReadException,
    ReadTimeout,
)

from netmiko.cisco_base_connection import CiscoBaseConnection, CiscoFileTransfer
from netmiko.base_connection import BaseConnection
from netmiko.scp_handler import BaseFileTransfer


class HuaweiBase(NoEnable, CiscoBaseConnection):
    
    def session_preparation(self) -> None:
        """Prepare the session after the connection has been established."""
        self.ansi_escape_codes = True
        # The _test_channel_read happens in special_login_handler()
        self.set_base_prompt()
        self.disable_paging(command="screen-length 0 temporary")

    def strip_ansi_escape_codes(self, string_buffer: str) -> str:
        """
        Huawei does a strange thing where they add a space and then add ESC[1D
        to move the cursor to the left one.

        The extra space is problematic.
        """
        code_cursor_left = chr(27) + r"\[\d+D"
        output = string_buffer
        pattern = rf" {code_cursor_left}"
        output = re.sub(pattern, "", output)

        return super().strip_ansi_escape_codes(output)

    def config_mode(
        self,
        config_command: str = "system-view",
        pattern: str = "",
        re_flags: int = 0,
    ) -> str:
        return super().config_mode(
            config_command=config_command, pattern=pattern, re_flags=re_flags
        )
    
    def send_config_from_file_expect(self, config_file=None, **kwargs):
        """
        Send configuration commands down the SSH channel from a file.

        The file is processed line-by-line and each command is sent down the
        SSH channel.

        **kwargs are passed to send_config_set method.

        :param config_file: Path to configuration file to be sent to the device
        :type config_file: str

        :param kwargs: params to be sent to send_config_set method
        :type kwargs: dict
        """
        with io.open(config_file, "rt", encoding="utf-8") as cfg_file:
            return self.send_config_set_expect(cfg_file, **kwargs)
    
    def send_config_set_expect(
        self,
        config_commands: Union[str, Sequence[str], Iterator[str], TextIO, None] = None,
        exit_config_mode: bool = True,
        read_timeout: Optional[float] = None,
        delay_factor: Optional[float] = None,
        max_loops: Optional[int] = None,
        strip_prompt: bool = False,
        strip_command: bool = False,
        config_mode_command: Optional[str] = None,
        cmd_verify: bool = True,
        enter_config_mode: bool = True,
        error_pattern: str = "",
        terminator: str = r"#",
        bypass_commands: Optional[str] = None,
        expect_string_mode: bool = False,
        expect_string_and_command: Optional[Dict[str, str]] = None
    ) -> str:
        if self.global_cmd_verify is not None:
            cmd_verify = self.global_cmd_verify

        if delay_factor is not None or max_loops is not None:
            warnings.warn(DELAY_FACTOR_DEPR_SIMPLE_MSG, DeprecationWarning)

            # Calculate an equivalent read_timeout (if using old settings)
            # Eliminate in Netmiko 5.x
            if read_timeout is None:
                max_loops = 150 if max_loops is None else max_loops
                delay_factor = 1.0 if delay_factor is None else delay_factor

                # If delay_factor has been set, then look at global_delay_factor
                delay_factor = self.select_delay_factor(delay_factor)

                read_timeout = self.calc_old_timeout(
                    max_loops=max_loops, delay_factor=delay_factor, loop_delay=0.1
                )

        if delay_factor is None:
            delay_factor = self.select_delay_factor(0)
        else:
            delay_factor = self.select_delay_factor(delay_factor)

        if read_timeout is None:
            read_timeout = 15
        else:
            read_timeout = read_timeout

        if config_commands is None:
            return ""
        elif isinstance(config_commands, str):
            config_commands = (config_commands,)

        if not hasattr(config_commands, "__iter__"):
            raise ValueError("Invalid argument passed into send_config_set")

        if expect_string_and_command is None:
            expect_string_and_command ={}
        elif isinstance(expect_string_and_command,dict):
            expect_string_and_command = expect_string_and_command
        else:
            raise ValueError("Invalid argument passed into send_config_set")
        
        if bypass_commands is None:
            # Commands where cmd_verify is automatically disabled reg-ex logical-or
            bypass_commands = r"^banner .*$"

        # Set bypass_commands="" to force no-bypass (usually for testing)
        bypass_detected = False
        if bypass_commands:
            # Make a copy of the iterator
            config_commands, config_commands_tmp = itertools.tee(config_commands, 2)
            bypass_detected = any(
                [True for cmd in config_commands_tmp if re.search(bypass_commands, cmd)]
            )
        if bypass_detected:
            cmd_verify = False

        # Send config commands
        output = ""
        if enter_config_mode:
            if config_mode_command:
                output += self.config_mode(config_mode_command)
            else:
                output += self.config_mode()

        # Perform output gathering line-by-line (legacy way)
        if self.fast_cli and self._legacy_mode and not error_pattern:
            if expect_string_mode:
                for cmd in config_commands:
                    self.write_channel(self.normalize_cmd(cmd))
                    time.sleep(delay_factor * 0.05)
                    check_expect_string_output = self.read_channel_timing(read_timeout = read_timeout)
                    for expect_string in list(expect_string_and_command.keys()):
                        if expect_string:
                            if re.search(re.escape(expect_string), check_expect_string_output, re.DOTALL):
                                output += check_expect_string_output
                                self.write_channel(self.normalize_cmd(expect_string_and_command[expect_string]))
                                output += self.read_channel_timing(read_timeout=read_timeout)
                                check_expect_string_output = ""
                                break
                        else:
                            continue
                    output += check_expect_string_output
            else:
                for cmd in config_commands:
                    self.write_channel(self.normalize_cmd(cmd))
            # Gather output
                output += self.read_channel_timing(read_timeout=read_timeout)
         
        elif not cmd_verify:
            for cmd in config_commands:
                self.write_channel(self.normalize_cmd(cmd))
                time.sleep(delay_factor * 0.05)

                # Gather the output incrementally due to error_pattern requirements
                if error_pattern:
                    output += self.read_channel_timing(read_timeout=read_timeout)
                    if re.search(error_pattern, output, flags=re.M):
                        msg = f"Invalid input detected at command: {cmd}"
                        raise ConfigInvalidException(msg)

            # Standard output gathering (no error_pattern)
            if not error_pattern:
                output += self.read_channel_timing(read_timeout=read_timeout)

        else:
            for cmd in config_commands:
                self.write_channel(self.normalize_cmd(cmd))

                # Make sure command is echoed
                output += self.read_until_pattern(
                    pattern=re.escape(cmd.strip()), read_timeout=read_timeout
                )

                # Read until next prompt or terminator (#); the .*$ forces read of entire line
                pattern = f"(?:{re.escape(self.base_prompt)}.*$|{terminator}.*$)"
                output += self.read_until_pattern(
                    pattern=pattern, read_timeout=read_timeout, re_flags=re.M
                )

                if error_pattern:
                    if re.search(error_pattern, output, flags=re.M):
                        msg = f"Invalid input detected at command: {cmd}"
                        raise ConfigInvalidException(msg)

        if exit_config_mode:
            output += self.exit_config_mode()
        output = self._sanitize_output(output)
        log.debug(f"{output}")
        return output

    def exit_config_mode(self, exit_config: str = "return", pattern: str = r">") -> str:
        """Exit configuration mode."""
        return super().exit_config_mode(exit_config=exit_config, pattern=pattern)

    def check_config_mode(
        self, check_string: str = "]", pattern: str = "", force_regex: bool = False
    ) -> bool:
        """Checks whether in configuration mode. Returns a boolean."""
        return super().check_config_mode(check_string=check_string)

    def set_base_prompt(
        self,
        pri_prompt_terminator: str = ">",
        alt_prompt_terminator: str = "]",
        delay_factor: float = 1.0,
        pattern: Optional[str] = None,
    ) -> str:
        """
        Sets self.base_prompt

        Used as delimiter for stripping of trailing prompt in output.

        Should be set to something that is general and applies in multiple contexts.
        For Huawei this will be the router prompt with < > or [ ] stripped off.

        This will be set on logging in, but not when entering system-view
        """

        prompt = super().set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            delay_factor=delay_factor,
            pattern=pattern,
        )

        # Strip off any leading HRP_. characters for USGv5 HA
        prompt = re.sub(r"^HRP_.", "", prompt, flags=re.M)

        # Strip off leading terminator
        prompt = prompt[1:]
        prompt = prompt.strip()
        self.base_prompt = prompt
        log.debug(f"prompt: {self.base_prompt}")
        return self.base_prompt

    def save_config(
        self, cmd: str = "save", confirm: bool = True, confirm_response: str = "y"
    ) -> str:
        """Save Config for HuaweiSSH"""
        return super().save_config(
            cmd=cmd, confirm=confirm, confirm_response=confirm_response
        )

    def cleanup(self, command: str = "quit") -> None:
        return super().cleanup(command=command)


class HuaweiSSH(HuaweiBase):
    """Huawei SSH driver."""

    def special_login_handler(self, delay_factor: float = 1.0) -> None:
        # Huawei prompts for password change before displaying the initial base prompt.
        # Search for that password change prompt or for base prompt.
        password_change_prompt = r"(Change now|Please choose)"
        prompt_or_password_change = r"(?:Change now|Please choose|[>\]])"
        data = self.read_until_pattern(pattern=prompt_or_password_change)
        if re.search(password_change_prompt, data):
            self.write_channel("N" + self.RETURN)
            self.read_until_pattern(pattern=r"[>\]]")


class HuaweiTelnet(HuaweiBase):
    """Huawei Telnet driver."""

    def telnet_login(
        self,
        pri_prompt_terminator: str = r"]\s*$",
        alt_prompt_terminator: str = r">\s*$",
        username_pattern: str = r"(?:user:|username|login|user name)",
        pwd_pattern: str = r"assword",
        delay_factor: float = 1.0,
        max_loops: int = 20,
    ) -> str:
        """Telnet login for Huawei Devices"""

        delay_factor = self.select_delay_factor(delay_factor)
        password_change_prompt = r"(Change now|Please choose 'YES' or 'NO').+"
        combined_pattern = r"({}|{}|{})".format(
            pri_prompt_terminator, alt_prompt_terminator, password_change_prompt
        )

        output = ""
        return_msg = ""
        i = 1
        while i <= max_loops:
            try:
                # Search for username pattern / send username
                output = self.read_until_pattern(
                    pattern=username_pattern, re_flags=re.I
                )
                return_msg += output
                self.write_channel(self.username + self.TELNET_RETURN)

                # Search for password pattern / send password
                output = self.read_until_pattern(pattern=pwd_pattern, re_flags=re.I)
                return_msg += output
                assert self.password is not None
                self.write_channel(self.password + self.TELNET_RETURN)

                # Waiting for combined output
                output = self.read_until_pattern(pattern=combined_pattern)
                return_msg += output

                # Search for password change prompt, send "N"
                if re.search(password_change_prompt, output):
                    self.write_channel("N" + self.TELNET_RETURN)
                    output = self.read_until_pattern(pattern=combined_pattern)
                    return_msg += output

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                    alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                self.write_channel(self.TELNET_RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1

            except EOFError:
                assert self.remote_conn is not None
                self.remote_conn.close()
                msg = f"Login failed: {self.host}"
                raise NetmikoAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        assert self.remote_conn is not None
        self.remote_conn.close()
        msg = f"Login failed: {self.host}"
        raise NetmikoAuthenticationException(msg)


class HuaweiVrpv8SSH(HuaweiSSH):
    def send_config_set(
        self,
        config_commands: Union[str, Sequence[str], Iterator[str], TextIO, None] = None,
        exit_config_mode: bool = False,
        **kwargs: Any,
    ) -> str:
        """Huawei VRPv8 requires you not exit from configuration mode."""
        return super().send_config_set(
            config_commands=config_commands, exit_config_mode=exit_config_mode, **kwargs
        )

    def commit(
        self,
        comment: str = "",
        read_timeout: float = 120.0,
        delay_factor: Optional[float] = None,
    ) -> str:
        """
        Commit the candidate configuration.

        Commit the entered configuration. Raise an error and return the failure
        if the commit fails.

        default:
           command_string = commit
        comment:
           command_string = commit comment <comment>

        delay_factor: Deprecated in Netmiko 4.x. Will be eliminated in Netmiko 5.
        """

        if delay_factor is not None:
            warnings.warn(DELAY_FACTOR_DEPR_SIMPLE_MSG, DeprecationWarning)

        error_marker = "Failed to generate committed config"
        command_string = "commit"

        if comment:
            command_string += f' comment "{comment}"'

        output = self.config_mode()
        output += self._send_command_str(
            command_string,
            strip_prompt=False,
            strip_command=False,
            read_timeout=read_timeout,
            expect_string=r"]",
        )
        output += self.exit_config_mode()

        if error_marker in output:
            raise ValueError(f"Commit failed with following errors:\n\n{output}")
        return output

    def save_config(self, *args: Any, **kwargs: Any) -> str:
        """Not Implemented"""
        raise NotImplementedError


class HuaweiFileTransfer(BaseFileTransfer):
    """Huawei SCP File Transfer driver."""
    def __init__(
            self,
            ssh_conn: BaseConnection,
            source_file: str,
            dest_file: str,
            file_system: str = "flash:",
            direction: str = "put",
            socket_timeout: float = 10.0,
            progress: Optional[Callable[..., Any]] = None,
            progress4: Optional[Callable[..., Any]] = None,
            hash_supported: bool = True,
    ) -> None:
        self.ssh_ctl_chan = ssh_conn
        self.source_file = source_file
        self.dest_file = dest_file
        self.direction = direction

        if hash_supported is False:
            raise ValueError("hash_supported=False is not supported for Huawei")

        if file_system:
            self.file_system = file_system
        else:
            raise ValueError("Destination file system must be specified for Huawei")

        if direction == "put":
            # self.source_md5 = self.file_md5(source_file)
            self.file_size = os.stat(source_file).st_size
        elif direction == "get":
            # self.source_md5 = self.remote_md5(remote_file=source_file)
            self.file_size = self.remote_file_size(remote_file=source_file)
        else:
            raise ValueError("Invalid direction specified")

        self.socket_timeout = socket_timeout
        self.progress = progress
        self.progress4 = progress4

    def check_file_exists(self, remote_cmd: str = "") -> bool:
        """Check if the dest_file already exists on the file system (return boolean)."""
        if self.direction == "put":
            if not remote_cmd:
                self.dest_file = self.dest_file.lower()
                remote_cmd = f"dir {self.file_system}/{self.dest_file}"
            remote_out = self.ssh_ctl_chan._send_command_str(remote_cmd)
            search_string = r"{}".format(self.dest_file)
            if "File can't be found" in remote_out:
                return False
            elif re.search(search_string, remote_out, flags=re.DOTALL):
                return True
            else:
                raise ValueError("Unexpected output from check_file_exists")
        elif self.direction == "get":
            return os.path.exists(self.dest_file)
        else:
            raise ValueError("Invalid value for file transfer direction.")

    def remote_file_size(
            self, remote_cmd: str = "", remote_file: Optional[str] = None
    ) -> int:
        """Get the file size of the remote file."""
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
            else:
                raise ValueError("Invalid value for file transfer direction.")

        if not remote_cmd:
            remote_cmd = f"dir {self.file_system}/{remote_file}"

        remote_out = self.ssh_ctl_chan._send_command_str(remote_cmd)
        if re.search("Such file or path doesn't exist", remote_out, flags=re.I):
            raise IOError("Unable to find file on remote system")
        # Match line containing file name
        escape_file_name = re.escape(remote_file)
        huawei_size_pattern = "(\d+((\,){0,1}\d+){0,3})"
        pattern = r"\d+\s+\S+\s+({}).*({}).*".format(huawei_size_pattern, escape_file_name)
        match = re.search(pattern, remote_out)
        if match:
            file_size = match.group(1)
            file_size = file_size.replace(",", "")
            return int(file_size)

        raise IOError("Unable to find file on remote system")


    def enable_scp(self, cmd: str = "") -> None:
        raise NotImplementedError

    def disable_scp(self, cmd: str = "") -> None:
        raise NotImplementedError

    def remote_space_available(self, search_pattern: str = r"(\d+((\,){0,1}\d+){0,3}) \w+ free") -> int:
        """Return space available on remote device."""
        remote_cmd = f"dir {self.file_system}"
        remote_output = self.ssh_ctl_chan._send_command_str(remote_cmd)
        match = re.search(search_pattern, remote_output)
        if match:
            if "KB" in match.group(0):
                return int(int(match.group(1).replace(",", ""))*1024)
            return int(match.group(1))
        else:
            msg = (
                f"pattern: {search_pattern} not detected in output:\n\n{remote_output}"
            )
            raise ValueError(msg)

    def local_space_available(self) -> int:
        """Return space available on local filesystem."""
        if sys.platform == "win32":
            import ctypes
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p("."), None, None, ctypes.pointer(free_bytes)
            )
            return free_bytes.value
        else:
            destination_stats = os.statvfs(".")
            return destination_stats.f_bsize * destination_stats.f_bavail

    def verify_space_available(self, search_pattern: str = r"(\d+((\,){0,1}\d+){0,3}) \w+ free") -> bool:
        """Verify sufficient space is available on destination file system (return boolean)."""
        if self.direction == "put":
            space_avail = self.remote_space_available(search_pattern=search_pattern)
        elif self.direction == "get":
            space_avail = self.local_space_available()
        if space_avail > self.file_size:
            return True
        return False

    def verify_file(self):
        """Verify the file has been transferred correctly."""
        return self.compare_size()
    
    def compare_size(self):
        """Compare size of file on network device to size of local file."""
        if self.direction == "put":
            remote_size = self.remote_file_size(remote_file=self.dest_file)
            return os.stat(self.source_file).st_size == remote_size
        elif self.direction == "get":
            local_size = self.remote_file_size(remote_file=self.source_file)
            return os.stat(self.dest_file).st_size == local_size