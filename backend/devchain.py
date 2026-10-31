"""
Local development chain management: start a Hardhat node, deploy, seed. Never targets a public network.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import requests

ROOT = Path(__file__).resolve().parents[1]
CHAIN_DIR = ROOT / "chain"
HARDHAT = CHAIN_DIR / "node_modules" / "hardhat" / "internal" / "cli" / "cli.js"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rpc_alive(url: str) -> bool:
    try:
        r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, timeout=2)
        return r.ok
    except Exception:  # noqa: BLE001
        return False


class DevChain:
    def __init__(self, port: Optional[int] = None, deployment_file: Optional[Path] = None, log_file: Optional[Path] = None):
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.deployment_file = Path(deployment_file) if deployment_file else CHAIN_DIR / "deployments" / f"dev-{self.port}.json"
        self.proc: Optional[subprocess.Popen] = None
        self.log_file = Path(log_file) if log_file else ROOT / "state" / f"hardhat-{self.port}.log"

    def _env(self) -> dict:
        env = dict(os.environ)
        env.update({"HARDHAT_PORT": str(self.port), "DEPLOYMENT_FILE": str(self.deployment_file)})
        return env

    def start(self, deploy: bool = True, timeout: float = 60.0) -> "DevChain":
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.deployment_file.parent.mkdir(parents=True, exist_ok=True)
        log = open(self.log_file, "w")
        self.proc = subprocess.Popen(["node", str(HARDHAT), "node", "--port", str(self.port)], cwd=CHAIN_DIR, stdout=log, stderr=subprocess.STDOUT, env=self._env())
        t0 = time.time()
        while time.time() - t0 < timeout:
            if rpc_alive(self.url):
                break
            if self.proc.poll() is not None:
                raise RuntimeError(f"hardhat node exited early, see {self.log_file}")
            time.sleep(0.4)
        else:
            self.stop()
            raise RuntimeError("hardhat node did not start in time")
        if deploy:
            self.deploy()
        return self

    def _run(self, script: str) -> None:
        r = subprocess.run(["node", str(HARDHAT), "run", f"scripts/{script}", "--network", "localhost"], cwd=CHAIN_DIR, env=self._env(), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"{script} failed:\n{r.stdout}\n{r.stderr}")

    def deploy(self) -> None:
        self._run("deploy.ts")
        self._run("seed.ts")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def __enter__(self) -> "DevChain":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
