"Reverse engineering framework in Python"

# Version generation stolen from Scapy

import os
import re
import subprocess

_MIASM_PKG_DIR = os.path.dirname(__file__)

def _version_from_git_describe():
    """
    Read the version from ``git describe``. It returns the latest tag with an
    optional suffix if the current directory is not exactly on the tag.

    Example::

        $ git describe --always
        v2.3.2-346-g164a52c075c8

    The tag prefix (``v``) and the git commit sha1 (``-g164a52c075c8``) are
    removed if present.

    If the current directory is not exactly on the tag, a ``.devN`` suffix is
    appended where N is the number of commits made after the last tag.

    Example::

        >>> _version_from_git_describe()
        '2.3.2.dev346'
    """
    if not os.path.isdir(os.path.join(os.path.dirname(_MIASM_PKG_DIR), '.git')):  # noqa: E501
        raise ValueError('not in miasm git repo')

    process = subprocess.Popen(['git', 'describe', '--always', '--tags'],
                               cwd=_MIASM_PKG_DIR,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = process.communicate()

    if process.returncode == 0:
        tag = out.decode().strip()
        match = re.match('^v?(.+?)-(\\d+)-g[a-f0-9]+$', tag)
        if match:
            # remove the 'v' prefix and add a '.devN' suffix
            return '%s.dev%s' % (match.group(1), match.group(2))
        else:
            # just remove the 'v' prefix
            return re.sub('^v', '', tag)
    else:
        raise subprocess.CalledProcessError(process.returncode, err)


def _version():
    version_file = os.path.join(_MIASM_PKG_DIR, 'VERSION')
    try:
        tag = _version_from_git_describe()
        # successfully read the tag from git, write it in VERSION for
        # installation and/or archive generation.
        with open(version_file, 'w') as fdesc:
            fdesc.write(tag)
        return tag
    except Exception:
        # failed to read the tag from git, try to read it from a VERSION file
        try:
            with open(version_file, 'r') as fdsec:
                tag = fdsec.read()
            return tag
        except Exception:
            # Rely on git archive "export-subst" git attribute.
            # See 'man gitattributes' for more details.
            git_archive_id = '$Format:%h %d$'
            sha1 = git_archive_id.strip().split()[0]
            match = re.search('tag:(\\S+)', git_archive_id)
            if match:
                return "git-archive.dev" + match.group(1)
            elif sha1:
                return "git-archive.dev" + sha1
            else:
                return 'unknown.version'


VERSION = __version__ = _version()
