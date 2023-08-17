import sys

__version__ = "0.0.2"
PY_MAJ_VER = 3
PY_MIN_VER = 7
MIN_PYTHON_VER = "3.7"


# Make sure user is using a valid Python version (for Netmiko)
def check_python_version():  # type: ignore
    python_snake = "\U0001F40D"

    # Use old-school .format() method in case someone tries to use Netmiko with very old Python
    msg = """

Netmiko_Huawei Version {net_ver} requires Python Version {py_ver} or higher.

""".format(
        net_ver=__version__, py_ver=MIN_PYTHON_VER
    )
    if sys.version_info.major != PY_MAJ_VER:
        raise ValueError(msg)
    elif sys.version_info.minor < PY_MIN_VER:
        # Why not :-)
        msg = msg.rstrip() + " {snake}\n\n".format(snake=python_snake)
        raise ValueError(msg)


check_python_version()  # type: ignore


import logging  # noqa


# Logging configuration
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())


from netmiko_huawei.custom_scp_functions import  progress_bar
from netmiko_huawei.custom_ssh_dispatcher import ConnectHandler, ConnUnify, ConnLogOnly, FileTransfer




__all__ = (
    "FileTransfer",
    "progress_bar",
    "ConnectHandler",
    "ConnUnify",
    "ConnLogOnly",
)

# Cisco cntl-shift-six sequence
CNTL_SHIFT_6 = chr(30)
