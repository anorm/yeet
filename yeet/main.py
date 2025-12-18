from pathlib import Path
from pydantic import BaseModel
import click
import json
import os
import requests
import shutil
import subprocess
import sys
import tempfile


class Receiver(BaseModel):
    nickname: str
    rx_gist_id: str
    tx_gist_url: str


class Config(BaseModel):
    receivers: list[Receiver] = []


CONFIG_FILE = Path.home() / ".config" / "yeet.conf"
CACHE_DIR = Path.home() / ".cache" / "yeet"


def load_config() -> Config:
    with open(CONFIG_FILE, "r") as f:
        contents = f.read()

    if not contents:
        return Config()

    return Config.model_validate_json(contents)


def save_config(config: Config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config.model_dump(), f, indent=2)


def get_gist(id):
    response = requests.get(f"https://api.github.com/gists/{id}")
    response.raise_for_status()
    gist = response.json()
    first_file = next(iter(gist.get("files", {})))
    if not first_file:
        raise RuntimeError("No file in gist")
    return gist.get("files").get(first_file).get("content")


def ensure_repo_exists(path: Path, url):
    proc = subprocess.run(
            ["git", "-C", path, "remote", "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True)

    must_clone = False
    if proc.returncode != 0:
        must_clone = True
    else:
        lines = proc.stdout.splitlines()
        if not any(True for x in lines if url in x):
            must_clone = True

    if must_clone:
        subprocess.run(
                ["git", "clone", url, path],
                check=True)


def set_repo_message(path, message):
    for item in os.listdir(path):
        if item == ".git":
            continue

        full_path = os.path.join(path, item)

        if os.path.isfile(full_path) or os.path.islink(full_path):
            os.unlink(full_path)
        elif os.path.isdir(full_path):
            shutil.rmtree(full_path)
    with open(path / "text.txt", "w") as f:
        f.write(message)


def commit_and_push(path):
    subprocess.run(
            ["git", "-C", path, "add", path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    subprocess.run(
            ["git", "-C", path, "commit", "-m", "updates"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    subprocess.run(
            ["git", "-c", "push.default=simple", "-C", path, "push"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)


def set_gist(nickname: str, gist_url: str, content: str):
    repo_path = CACHE_DIR / nickname / "tx"
    ensure_repo_exists(repo_path, gist_url)
    set_repo_message(repo_path, content)
    commit_and_push(repo_path)


def fingerprint_from_pattern(pattern):
    proc = subprocess.run(
        ["gpg", "--list-keys", "--with-colons", pattern],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True)

    lines = proc.stdout.splitlines()
    it = iter(lines)
    if not next((x for x in it if x.startswith("pub:")), None):
        return None
    fpr = next((x for x in it if x.startswith("fpr:")), None)
    if fpr is None:
        return None
    return fpr.split(":")[9]


def decrypt(encrypted, fingerprint):
    with tempfile.TemporaryFile() as status_fd:
        proc = subprocess.run(
                ["gpg", "--batch", "--yes", "--status-fd", str(status_fd.fileno()), "--decrypt"],
                input=encrypted,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=[status_fd.fileno()],
                text=True)
        status_fd.seek(0)
        status = status_fd.read().decode().splitlines()
        sig_line = next((s for s in status if " VALIDSIG " in s), None)
        if not sig_line:
            raise click.ClickException("Unable to verify signature (VALIDSIG not found)")
        if fingerprint not in sig_line:
            raise click.ClickException("Signature valid but from different sender")
    return proc.stdout


def encrypt(cleartext, receiver_fingerprint):
    proc = subprocess.run(
            ["gpg", "--encrypt", "--recipient", receiver_fingerprint, "--sign", "--armor"],
            input=cleartext.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise click.ClickException("Unable to encrypt message\n" + proc.stderr.read())

    return proc.stdout.decode()


@click.group()
def main():
    if not shutil.which("gpg"):
        raise click.ClickException("'gpg' not found")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.touch(exist_ok=True)


@main.command()
@click.argument("nickname", type=str)
@click.argument("rx-gist-id", type=str)
@click.argument("tx-gist-url", type=str)
def add_receiver(nickname: str, rx_gist_id: str, tx_gist_url: str):
    if not fingerprint_from_pattern(nickname):
        raise click.ClickException(f"No GPG public key found for '{nickname}'")

    config = load_config()
    if nickname in (r.nickname for r in config.receivers):
        raise click.ClickException(f"{nickname} is already configured")

    r = Receiver(nickname=nickname,
                 rx_gist_id=rx_gist_id,
                 tx_gist_url=tx_gist_url)
    config.receivers.append(r)
    save_config(config)


@main.command(name="from")
@click.argument("nickname", type=str)
def from_(nickname):
    config = load_config()
    receiver = next((r for r in config.receivers if r.nickname == nickname), None)
    if not receiver:
        raise click.ClickException(f"'{nickname}' not found")
    encrypted = get_gist(receiver.rx_gist_id)
    decrypted = decrypt(encrypted, fingerprint_from_pattern(nickname))
    click.echo(decrypted)


@main.command(name="to")
@click.argument("nickname", type=str)
@click.argument("message_file", type=click.File("rb"), default=sys.stdin)
def to_(nickname: str, message_file):
    config = load_config()
    receiver = next((r for r in config.receivers if r.nickname == nickname), None)
    if not receiver:
        raise click.ClickException(f"'{nickname}' not found")
    fingerprint = fingerprint_from_pattern(nickname)
    if not fingerprint:
        raise click.ClickException(f"No GPG public key found for '{nickname}'")
    cleartext = message_file.read()
    encrypted = encrypt(cleartext, fingerprint)
    set_gist(nickname, receiver.tx_gist_url, encrypted)


if __name__ == "__main__":
    main()
