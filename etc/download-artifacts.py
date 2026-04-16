# Download libmongocrypt artifacts to upload to a GitHub release.
#
# /// script
# dependencies = [
#   "pyyaml",
#   "requests",
# ]
# ///

import argparse
import requests
import yaml
from pathlib import Path
from urllib.parse import urlsplit


def download_file(url: str):
    url_parts = urlsplit(url)
    path = Path(url_parts.path)
    filename = path.name
    destination_dir = Path("_build/artifacts")
    destination_dir.mkdir(exist_ok=True, parents=True)
    destination = destination_dir / filename
    print(f"Downloading {url} to {destination}")
    with requests.get(url, stream=True) as resp:
        with destination.open("wb") as file:
            for chunk in resp.iter_content(chunk_size=8192):
                file.write(chunk)


def main():
    parser = argparse.ArgumentParser(description="Download release artifacts from an Evergreen version")
    parser.add_argument("version_id", help="Evergreen version ID. (e.g. https://evergreen.mongodb.com/version/<version_id>)")
    args = parser.parse_args()

    version_id = args.version_id

    # Get Evergreen API credentials:
    path: Path = Path().home() / ".evergreen.yml"
    with path.open() as file:
        evg_settings = yaml.load(file, Loader=yaml.FullLoader)

    api_server_host = "https://evergreen.mongodb.com/rest/v2"
    api_key = evg_settings["api_key"]
    api_user = evg_settings["user"]
    headers = {'Api-User': api_user, 'Api-Key': api_key}

    resp: requests.Response = requests.get(
        f"{api_server_host}/versions/{version_id}/builds",
        params={"include_task_info": "true"},
        headers=headers)
    builds = resp.json()

    for build in builds:
        for task_info in build["task_cache"]:
            if task_info["display_name"] == "upload-release":
                task_id = task_info["id"]
                resp = requests.get(
                    f"{api_server_host}/tasks/{task_id}", headers=headers)
                task = resp.json()
                for artifact in task["artifacts"]:
                    download_file(artifact["url"])


if __name__ == "__main__":
    main()
