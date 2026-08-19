from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILES = sorted((ROOT / "infra/compose").glob("*.Dockerfile"))

NON_ROOT_USERS = {
    "node",
    "nobody",
    "nouser",
    "nonroot",
    "10001",
    "65532",
}
USER_RE = re.compile(r"^\s*USER\s+(?P<user>[\w.-]+)(?::(?P<group>[\w.-]+))?\s*$")


class ContainerHardeningTests(unittest.TestCase):
    """Non-root execution is a threat-model control for every composed image.

    Each Dockerfile must end its user context on a non-root identity, must
    never switch back to root afterwards, and must not re-enter root through a
    start command.
    """

    def test_every_dockerfile_has_a_non_root_user_directive(self) -> None:
        self.assertGreaterEqual(len(DOCKERFILES), 3, "expected the compose Dockerfiles to be present")
        for dockerfile in DOCKERFILES:
            with self.subTest(dockerfile=dockerfile.name):
                text = dockerfile.read_text(encoding="utf-8")
                users = [match for match in (USER_RE.match(line) for line in text.splitlines()) if match]
                self.assertTrue(users, f"{dockerfile.name} has no USER directive")
                final_user = users[-1].group("user")
                self.assertIn(final_user, NON_ROOT_USERS, f"{dockerfile.name} must run as a non-root user, got {final_user!r}")
                self.assertNotIn("USER root", text)
                self.assertNotIn("sudo", text)
                self.assertNotIn("gosu root", text)

    def test_dockerfile_runtime_commands_run_after_the_final_user(self) -> None:
        for dockerfile in DOCKERFILES:
            with self.subTest(dockerfile=dockerfile.name):
                lines = dockerfile.read_text(encoding="utf-8").splitlines()
                user_lines = [index for index, line in enumerate(lines) if USER_RE.match(line)]
                self.assertTrue(user_lines, f"{dockerfile.name} has no USER directive")
                final_user_index = user_lines[-1]
                for index in range(final_user_index + 1, len(lines)):
                    line = lines[index].strip()
                    if line.startswith("#") or not line:
                        continue
                    # A later RUN/CMD/ENTRYPOINT must not escalate privileges.
                    self.assertNotIn("USER root", line)
                    self.assertNotIn("adduser", line)
                    self.assertNotIn("useradd", line)


if __name__ == "__main__":
    unittest.main()
