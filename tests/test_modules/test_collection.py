"""Tests for collection modules (TA0009)."""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

from core.models import Severity, Status, Tactic, SessionType, Target
from core.session import CommandResult, Session


def make_session(responses: dict[str, CommandResult] | None = None) -> Session:
    target = Target(host="localhost", session_type=SessionType.LOCAL)
    session = Session(target)
    session._connected = True
    default = CommandResult(stdout="", stderr="", return_code=1)
    resp = responses or {}

    def mock_execute(command: str, timeout: int = 60, sudo: bool = False) -> CommandResult:
        for pattern, result in resp.items():
            if pattern in command:
                return result
        return default

    session.execute = MagicMock(side_effect=mock_execute)
    return session


class TestAitmCollectionCheck:
    def test_attributes(self):
        from modules.collection.T1557_aitm import AitmCollectionCheck
        m = AitmCollectionCheck()
        assert m.TECHNIQUE_ID == "T1557"
        assert m.TACTIC == Tactic.COLLECTION

    def test_promiscuous_mode(self):
        from modules.collection.T1557_aitm import AitmCollectionCheck
        session = make_session({
            "which arpspoof": CommandResult("", "", 1),
            "which ettercap": CommandResult("", "", 1),
            "which bettercap": CommandResult("", "", 1),
            "which tcpdump": CommandResult("", "", 1),
            "which tshark": CommandResult("", "", 1),
            "ip link show": CommandResult("eth0: <BROADCAST,MULTICAST,PROMISC,UP>\n", "", 0),
            "sysctl -n net.ipv4.ip_forward": CommandResult("0\n", "", 0),
        })
        m = AitmCollectionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("promiscuous" in f.title.lower() for f in result.findings)


class TestArchiveDataCheck:
    def test_attributes(self):
        from modules.collection.T1560_archive_data import ArchiveDataCheck
        m = ArchiveDataCheck()
        assert m.TECHNIQUE_ID == "T1560"

    def test_archive_tools(self):
        from modules.collection.T1560_archive_data import ArchiveDataCheck
        session = make_session({
            "which tar": CommandResult("/usr/bin/tar\n", "", 0),
            "which gzip": CommandResult("/usr/bin/gzip\n", "", 0),
            "which bzip2": CommandResult("", "", 1),
            "which xz": CommandResult("", "", 1),
            "which zip": CommandResult("", "", 1),
            "which 7z": CommandResult("", "", 1),
            "which rar": CommandResult("", "", 1),
            "which cpio": CommandResult("", "", 1),
            "which gpg": CommandResult("", "", 1),
        })
        m = ArchiveDataCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestAudioCaptureCheck:
    def test_attributes(self):
        from modules.collection.T1123_audio_capture import AudioCaptureCheck
        m = AudioCaptureCheck()
        assert m.TECHNIQUE_ID == "T1123"

    def test_clean(self):
        from modules.collection.T1123_audio_capture import AudioCaptureCheck
        m = AudioCaptureCheck()
        result = m.check(make_session({}))
        assert result.status == Status.NOT_VULNERABLE


class TestAutomatedCollectionCheck:
    def test_attributes(self):
        from modules.collection.T1119_automated_collection import AutomatedCollectionCheck
        m = AutomatedCollectionCheck()
        assert m.TECHNIQUE_ID == "T1119"

    def test_locate_db(self):
        from modules.collection.T1119_automated_collection import AutomatedCollectionCheck
        session = make_session({
            "which find": CommandResult("/usr/bin/find\n", "", 0),
            "which grep": CommandResult("/usr/bin/grep\n", "", 0),
            "which awk": CommandResult("/usr/bin/awk\n", "", 0),
            "which sed": CommandResult("/usr/bin/sed\n", "", 0),
            "mlocate.db": CommandResult("exists\n", "", 0),
            "plocate.db": CommandResult("", "", 1),
            "which python3": CommandResult("", "", 1),
            "which perl": CommandResult("", "", 1),
            "which ruby": CommandResult("", "", 1),
        })
        m = AutomatedCollectionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestClipboardDataCheck:
    def test_attributes(self):
        from modules.collection.T1115_clipboard_data import ClipboardDataCheck
        m = ClipboardDataCheck()
        assert m.TECHNIQUE_ID == "T1115"

    def test_clipboard_tool(self):
        from modules.collection.T1115_clipboard_data import ClipboardDataCheck
        session = make_session({
            "which xclip": CommandResult("/usr/bin/xclip\n", "", 0),
            "which xsel": CommandResult("", "", 1),
            "which wl-copy": CommandResult("", "", 1),
            "which wl-paste": CommandResult("", "", 1),
            "which xdotool": CommandResult("", "", 1),
            "echo $DISPLAY": CommandResult("", "", 0),
        })
        m = ClipboardDataCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestDataRepositoriesCheck:
    def test_attributes(self):
        from modules.collection.T1213_data_repositories import DataRepositoriesCheck
        m = DataRepositoriesCheck()
        assert m.TECHNIQUE_ID == "T1213"

    def test_git_repos_found(self):
        from modules.collection.T1213_data_repositories import DataRepositoriesCheck
        session = make_session({
            "which mysql": CommandResult("", "", 1),
            "which psql": CommandResult("", "", 1),
            "which mongo": CommandResult("", "", 1),
            "which redis-cli": CommandResult("", "", 1),
            "find /opt /srv /home": CommandResult("/opt/app/.git\n/srv/code/.git\n", "", 0),
            "test -d /var/www/wiki": CommandResult("", "", 1),
            "test -d /opt/confluence": CommandResult("", "", 1),
            "test -d /opt/mediawiki": CommandResult("", "", 1),
            "test -d /srv/gitea": CommandResult("", "", 1),
        })
        m = DataRepositoriesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestDataLocalSystemCheck:
    def test_attributes(self):
        from modules.collection.T1005_data_local_system import DataLocalSystemCheck
        m = DataLocalSystemCheck()
        assert m.TECHNIQUE_ID == "T1005"

    def test_readable_shadow(self):
        from modules.collection.T1005_data_local_system import DataLocalSystemCheck
        session = make_session({
            "test -r /etc/shadow": CommandResult("readable\n", "", 0),
            "test -r /etc/gshadow": CommandResult("", "", 1),
            "test -r /etc/sudoers": CommandResult("", "", 1),
            "find /home /root -name 'id_rsa'": CommandResult("", "", 1),
            "find /home /root -name '.bash_history'": CommandResult("", "", 1),
            "grep -rli 'password": CommandResult("", "", 1),
        })
        m = DataLocalSystemCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("shadow" in f.title.lower() for f in result.findings)


class TestNetworkSharedDriveCheck:
    def test_attributes(self):
        from modules.collection.T1039_network_shared_drive import NetworkSharedDriveCheck
        m = NetworkSharedDriveCheck()
        assert m.TECHNIQUE_ID == "T1039"

    def test_mounted_share(self):
        from modules.collection.T1039_network_shared_drive import NetworkSharedDriveCheck
        session = make_session({
            "mount -t nfs": CommandResult("server:/export on /mnt/share type nfs (rw)\n", "", 0),
            "grep -E 'nfs|cifs'": CommandResult("", "", 1),
            "which smbclient": CommandResult("", "", 1),
            "which showmount": CommandResult("", "", 1),
            "which mount.cifs": CommandResult("", "", 1),
            "which mount.nfs": CommandResult("", "", 1),
        })
        m = NetworkSharedDriveCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestRemovableMediaCheck:
    def test_attributes(self):
        from modules.collection.T1025_removable_media import RemovableMediaCheck
        m = RemovableMediaCheck()
        assert m.TECHNIQUE_ID == "T1025"


class TestDataStagedCheck:
    def test_attributes(self):
        from modules.collection.T1074_data_staged import DataStagedCheck
        m = DataStagedCheck()
        assert m.TECHNIQUE_ID == "T1074"

    def test_large_files_in_tmp(self):
        from modules.collection.T1074_data_staged import DataStagedCheck
        session = make_session({
            "test -w /tmp": CommandResult("", "", 0),
            "df -h /tmp": CommandResult("/dev/sda1  50G  20G  30G  40% /tmp\n", "", 0),
            "mount": CommandResult("/dev/sda1 on /tmp type ext4 (rw,nosuid,nodev)\n", "", 0),
            "test -w /var/tmp": CommandResult("", "", 1),
            "test -w /dev/shm": CommandResult("", "", 1),
            "find /tmp /var/tmp /dev/shm -type f -size": CommandResult("/tmp/dump.sql\n", "", 0),
            "find /tmp /var/tmp -maxdepth 2 -name '.*'": CommandResult("", "", 1),
        })
        m = DataStagedCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestEmailCollectionCheck:
    def test_attributes(self):
        from modules.collection.T1114_email_collection import EmailCollectionCheck
        m = EmailCollectionCheck()
        assert m.TECHNIQUE_ID == "T1114"


class TestInputCaptureCheck:
    def test_attributes(self):
        from modules.collection.T1056_input_capture import InputCaptureCheck
        m = InputCaptureCheck()
        assert m.TECHNIQUE_ID == "T1056"
        assert m.TACTIC == Tactic.COLLECTION

    def test_input_devices_readable(self):
        from modules.collection.T1056_input_capture import InputCaptureCheck
        session = make_session({
            "ls -la /dev/input/event": CommandResult("crw-rw---- 1 root input /dev/input/event0\n", "", 0),
            "test -r /dev/input/event0": CommandResult("readable\n", "", 0),
            "which logkeys": CommandResult("", "", 1),
            "which xinput": CommandResult("", "", 1),
            "which showkey": CommandResult("", "", 1),
            "which evtest": CommandResult("", "", 1),
            "/proc/sys/kernel/yama/ptrace_scope": CommandResult("1\n", "", 0),
        })
        m = InputCaptureCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestScreenCaptureCheck:
    def test_attributes(self):
        from modules.collection.T1113_screen_capture import ScreenCaptureCheck
        m = ScreenCaptureCheck()
        assert m.TECHNIQUE_ID == "T1113"


class TestVideoCaptureCheck:
    def test_attributes(self):
        from modules.collection.T1125_video_capture import VideoCaptureCheck
        m = VideoCaptureCheck()
        assert m.TECHNIQUE_ID == "T1125"

    def test_video_device(self):
        from modules.collection.T1125_video_capture import VideoCaptureCheck
        session = make_session({
            "ls /dev/video": CommandResult("/dev/video0\n", "", 0),
            "test -r /dev/video0": CommandResult("readable\n", "", 0),
            "which v4l2-ctl": CommandResult("", "", 1),
            "which ffmpeg": CommandResult("", "", 1),
            "which cheese": CommandResult("", "", 1),
            "which guvcview": CommandResult("", "", 1),
        })
        m = VideoCaptureCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestCollectionCommon:
    MODULE_CLASSES = [
        ("modules.collection.T1557_aitm", "AitmCollectionCheck"),
        ("modules.collection.T1560_archive_data", "ArchiveDataCheck"),
        ("modules.collection.T1123_audio_capture", "AudioCaptureCheck"),
        ("modules.collection.T1119_automated_collection", "AutomatedCollectionCheck"),
        ("modules.collection.T1115_clipboard_data", "ClipboardDataCheck"),
        ("modules.collection.T1213_data_repositories", "DataRepositoriesCheck"),
        ("modules.collection.T1005_data_local_system", "DataLocalSystemCheck"),
        ("modules.collection.T1039_network_shared_drive", "NetworkSharedDriveCheck"),
        ("modules.collection.T1025_removable_media", "RemovableMediaCheck"),
        ("modules.collection.T1074_data_staged", "DataStagedCheck"),
        ("modules.collection.T1114_email_collection", "EmailCollectionCheck"),
        ("modules.collection.T1056_input_capture", "InputCaptureCheck"),
        ("modules.collection.T1113_screen_capture", "ScreenCaptureCheck"),
        ("modules.collection.T1125_video_capture", "VideoCaptureCheck"),
    ]

    def test_all_tactic_is_collection(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert cls().TACTIC == Tactic.COLLECTION, f"{cls_name} tactic wrong"

    def test_all_safe_mode(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert cls().SAFE_MODE is True

    def test_all_have_mitigations(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert len(cls().get_mitigations()) > 0

    def test_simulate_delegates(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            instance = cls()
            session = make_session({})
            assert instance.check(session).status == instance.simulate(session).status
