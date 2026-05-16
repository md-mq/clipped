from mock import patch
import os
from unittest import TestCase

from clipped.config.contexts import get_project_path
from clipped.config.manager import ConfigManager


class TestBaseConfigManger(TestCase):
    class DummyConfigManger(ConfigManager):
        _PROJECT = ".foo"

    def test_default_props(self):
        assert self.DummyConfigManger.is_global() is False
        assert self.DummyConfigManger.is_local() is False
        assert self.DummyConfigManger.is_all_visibility() is False
        assert self.DummyConfigManger.IN_PROJECT_DIR is False
        assert self.DummyConfigManger.CONFIG_FILE_NAME is None
        assert self.DummyConfigManger.CONFIG is None

    @patch("clipped.config.manager.os.path.expanduser")
    def test_get_config_filepath(self, expanduser):
        self.DummyConfigManger.CONFIG_FILE_NAME = "testing"

        # Test configuration
        # Set IS_GLOBAL = False
        self.DummyConfigManger.VISIBILITY = ConfigManager.Visibility.LOCAL

        # Set IN_PROJECT_DIR = True
        self.DummyConfigManger.IN_PROJECT_DIR = True
        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file1 = self.DummyConfigManger.get_config_filepath(create=True)
        assert path_fct.call_count == 1

        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file2 = self.DummyConfigManger.get_config_filepath(create=False)
        assert path_fct.call_count == 0
        assert config_file1 == config_file2
        assert config_file1 == os.path.join(".", ".foo", "testing")

        # Test configuration
        # Set IN_PROJECT_DIR = False
        self.DummyConfigManger.IN_PROJECT_DIR = False
        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file1 = self.DummyConfigManger.get_config_filepath(create=True)
        assert path_fct.call_count == 1

        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file2 = self.DummyConfigManger.get_config_filepath(create=False)
        assert path_fct.call_count == 0
        assert config_file1 == config_file2
        assert config_file1 == os.path.join(".", "testing")

        # Test configuration
        # Set IS_GLOBAL = True
        self.DummyConfigManger.VISIBILITY = ConfigManager.Visibility.GLOBAL

        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file1 = self.DummyConfigManger.get_config_filepath(create=True)
        assert path_fct.call_count == 1

        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file2 = self.DummyConfigManger.get_config_filepath(create=False)
        assert path_fct.call_count == 0
        assert config_file1 == config_file2
        assert config_file1 == os.path.join(get_project_path(".foo"), "testing")

        # Test configuration
        # Set CONFIG_PATH = /tmp
        self.DummyConfigManger.CONFIG_PATH = "/tmp"

        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file3 = self.DummyConfigManger.get_config_filepath(create=True)
        assert path_fct.call_count == 1

        with patch.object(self.DummyConfigManger, "_create_dir") as path_fct:
            config_file4 = self.DummyConfigManger.get_config_filepath(create=False)
        assert path_fct.call_count == 0
        assert config_file3 == config_file4
        assert config_file3 == os.path.join("/tmp/", ".foo", "testing")

    def test_is_initialized(self):
        with patch.object(self.DummyConfigManger, "get_config_filepath") as path_fct1:
            with patch("clipped.config.manager.os.path.isfile") as path_fct2:
                self.DummyConfigManger.is_initialized()

        assert path_fct1.call_count == 1
        assert path_fct1.call_args_list[0][0] == ()
        assert path_fct1.call_args_list[0][1] == {"create": False}
        assert path_fct2.call_count == 1
