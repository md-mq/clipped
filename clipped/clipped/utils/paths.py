import logging
import os
import shutil
import tarfile
import tempfile

from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, List, Optional, Pattern, Tuple, Union

from clipped.utils.lists import to_list

_logger = logging.getLogger("clipped.utils.paths")


def check_or_create_path(path: Optional[str] = None, is_dir: bool = False):
    if not is_dir:
        path = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def delete_path(path: str, reraise: bool = False):
    if not os.path.exists(path):
        return
    try:
        if os.path.isfile(path):
            os.remove(path)
        else:
            shutil.rmtree(path)
    except OSError as e:
        if reraise:
            raise e
        _logger.warning("Could not delete path `%s`", path)


def create_path(path: str, reraise: bool = False) -> None:
    try:
        os.mkdir(path)
    except FileExistsError:
        pass
    except OSError as e:
        if reraise:
            raise e
        _logger.warning("Could not create path `%s`, exception %s", path, e)


def get_tmp_path(path: str) -> str:
    return os.path.join("/tmp", path)


def create_tmp_dir(dir_name: str) -> None:
    create_path(get_tmp_path(dir_name))


def delete_tmp_dir(dir_name: str) -> None:
    delete_path(get_tmp_path(dir_name))


def copy_to_tmp_dir(path: str, dir_name: str, reraise: bool = False) -> str:
    tmp_path = get_tmp_path(dir_name)
    if os.path.exists(tmp_path):
        return tmp_path
    try:
        shutil.copytree(path, tmp_path)
    except FileExistsError as e:
        if reraise:
            raise e
        _logger.warning("Path already exists `%s`, exception %s", path, e)
    return tmp_path


def copy_file(filename: str, path_to: str, use_basename: bool = True) -> Optional[str]:
    if use_basename:
        path_to = append_basename(path_to, filename)

    if filename == path_to:
        return

    check_or_create_path(path_to, is_dir=False)
    shutil.copy(filename, path_to)
    return path_to


@contextmanager
def get_files_by_paths(file_type: str, filepaths: List[str]) -> Tuple[List[str], int]:
    local_files = []
    total_file_size = 0

    for filepath in filepaths:
        local_files.append(
            (file_type, (unix_style_path(filepath), open(filepath, "rb"), "text/plain"))
        )
        total_file_size += os.path.getsize(filepath)

    yield local_files, total_file_size

    # close all files to avoid WindowsError: [Error 32]
    for f in local_files:
        f[1][1].close()


def get_files_and_dirs_in_path(
    path: str,
    exclude: Optional[List[str]] = None,
    collect_dirs: bool = False,
) -> Tuple[List[str], List[str]]:
    result_files = []
    result_dirs = []
    exclude = to_list(exclude, check_none=True)
    for root, dirs, files in os.walk(path, topdown=True):
        if exclude:
            dirs[:] = [d for d in dirs if d not in exclude]
        _logger.debug("Root:%s, Dirs:%s", root, dirs)
        for file_name in files:
            result_files.append(os.path.join(root, file_name))
        if collect_dirs:
            for dir_name in dirs:
                result_dirs.append(os.path.join(root, dir_name))
    return result_files, result_dirs


def get_files_in_path(path: str, exclude: Optional[List[str]] = None) -> List[str]:
    return get_files_and_dirs_in_path(path, exclude, False)[0]


def get_dirs_under_path(path: str) -> List[str]:
    return [
        name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))
    ]


def delete_old_files(path: str, hours: Optional[float] = 24) -> Tuple[int, List[str]]:
    """
    Delete files older than specified hours in the given directory and its subdirectories.

    Args:
        path (str): Directory path to start searching from
        hours (float): Number of hours, files older than this will be deleted

    Returns:
        tuple[int, list[str]]: Count of deleted files and list of deleted file paths
    """
    deleted_count = 0
    deleted_files = []
    current_time = datetime.now()
    cutoff_time = current_time - timedelta(hours=hours)

    files = get_files_in_path(path)
    for file_path in files:
        try:
            # Get the last modified time of the file
            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))

            # Check if file is older than cutoff time
            if file_time < cutoff_time:
                os.remove(file_path)
                deleted_count += 1
                deleted_files.append(file_path)
        except (OSError, PermissionError) as e:
            _logger.debug(f"Error deleting old file {file_path}: {e}")

    return deleted_count, deleted_files


@contextmanager
def get_files_in_path_context(
    path: str, exclude: Optional[List[str]] = None
) -> List[str]:
    """
    Gets all the files under a certain path.

    Args:
        path: `str`. The path to traverse for collecting files.
        exclude: `list`. List of paths to excludes.

    Returns:
         list of files collected under the path.
    """
    yield get_files_in_path(path, exclude=exclude)


def unix_style_path(path) -> str:
    if os.path.sep != "/":
        return path.replace(os.path.sep, "/")
    return path


def create_tarfile(
    files: List[str], tar_path: str, relative_to: Optional[str] = None
) -> None:
    """Create a tar file based on the list of files passed"""
    with tarfile.open(tar_path, "w:gz") as tar:
        for f in files:
            arcname = os.path.relpath(f, relative_to) if relative_to else None
            tar.add(f, arcname=arcname)


@contextmanager
def create_tarfile_from_path(
    files: List[str], path_name: str, relative_to: Optional[str] = None
) -> str:
    """Create a tar file based on the list of files passed"""
    fd, filename = tempfile.mkstemp(prefix=path_name, suffix=".tar.gz")
    create_tarfile(files, filename, relative_to)
    yield filename

    # clear
    os.close(fd)
    os.remove(filename)


def untar_file(
    filename: Optional[str] = None,
    delete_tar: bool = True,
    extract_path: Optional[str] = None,
    use_filepath: bool = True,
):
    extract_path = extract_path or "."
    if use_filepath:
        extract_path = os.path.join(extract_path, filename.split(".tar.gz")[0])
    check_or_create_path(extract_path, is_dir=True)
    _logger.info("Untarring the content of the file ...")
    # Untar the file
    with tarfile.open(filename) as tar:
        tar.extractall(extract_path)
    if delete_tar:
        _logger.info("Cleaning up the tar file ...")
        os.remove(filename)
    return extract_path


def move_recursively(src: str, dst: str):
    files = os.listdir(src)

    for f in files:
        shutil.move(os.path.join(src, f), dst)


def append_basename(path: str, filename: str):
    """
    Adds the basename of the filename to the path.

    Args:
        path: `str`. The path to append the basename to.
        filename: `str`. The filename to extract the base name from.

    Returns:
         str
    """
    return os.path.join(path, os.path.basename(filename))


def check_dirname_exists(path: str, is_dir: bool = False, reraise: bool = True):
    if not is_dir:
        path = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(path):
        error = "The parent path is not a directory {}".format(path)
        if reraise:
            raise OSError(error)
        _logger.warning(error)
        return False
    return True


def create_project_tmp(project_name: str) -> str:
    base_path = os.path.join("/tmp", project_name)
    if not os.path.exists(base_path):
        try:
            os.makedirs(base_path)
        except OSError:
            # Except permission denied and potential race conditions
            # in multi-threaded environments.
            _logger.warning("Could not create config directory `%s`", base_path)
    return base_path


def get_path_extension(filepath: str) -> str:
    return ".".join(os.path.basename(filepath).split(".")[1:]).lower()


def get_base_filename(filepath: str) -> str:
    return os.path.basename(filepath).split(".")[0]


def module_type(obj: Any, type_pattern: Union[str, Pattern]) -> bool:
    obj_type = type(obj)
    module = obj_type.__module__
    name = obj_type.__name__
    actual_fqn = "%s.%s" % (module, name)
    if isinstance(type_pattern, str):
        return type_pattern == actual_fqn
    else:
        return type_pattern.match(actual_fqn) is not None


def copy_file_path(from_path: str, asset_path: str):
    check_or_create_path(asset_path, is_dir=False)
    shutil.copy(from_path, asset_path)


def copy_dir_path(from_path: str, asset_path: str):
    check_or_create_path(asset_path, is_dir=False)
    shutil.copytree(from_path, asset_path)


def copy_file_or_dir_path(
    from_path: str, asset_path: str, use_basename: bool = False
) -> str:
    if use_basename:
        dir_name = os.path.basename(os.path.normpath(from_path))
        asset_path = (
            os.path.join(asset_path, dir_name) if asset_path is not None else dir_name
        )
    check_or_create_path(asset_path, is_dir=False)
    if os.path.isfile(from_path):
        try:
            shutil.copy(from_path, asset_path)
        except shutil.SameFileError:
            pass
    else:
        shutil.copytree(from_path, asset_path)

    return asset_path


def get_relative_path_to(base_path, paths: List[str]) -> List[str]:
    results = []
    if not paths:
        return results
    for d in paths:
        if not os.path.isabs(d):
            results.append(os.path.join(base_path, d))
        else:
            results.append(d)

    return results


RW_R_R_PERMISSIONS = 0o644


def set_permissions(
    path: str, permissions: int = RW_R_R_PERMISSIONS, reraise: bool = False
):
    try:
        os.chmod(path, permissions or RW_R_R_PERMISSIONS)
    except OSError as e:
        if reraise:
            raise e
        _logger.info("Could not set permissions `%s`", path)
