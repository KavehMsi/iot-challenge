import argparse
import os
import shutil

import docker
import psutil
import yaml
from docker.errors import NotFound

ENV_PREFIX = "SCTL_"
LOG_ROTATE_CONFIG_PATH = "/etc/logrotate.d/suricata"


def validate_iface(name: str):
    interfaces = psutil.net_if_addrs().keys()
    if name not in interfaces:
        raise ValueError(
            f"IFACE '{name}' does not exist on this system. Available: {', '.join(interfaces)}"
        )
    return name


def validate_cpu_workers(value: int):
    logical_cores = os.cpu_count() or 1
    if value < 1 or value > logical_cores:
        raise ValueError(
            f"CPU_WORKERS must be between 1 and {logical_cores}, got {value}"
        )
    return value


def validate_memcap_mb(value: int):
    total_mb = int(psutil.virtual_memory().total / 1024 / 1024)
    if value < 128 or value > total_mb:
        raise ValueError(f"MEMCAP_MB must be between 128 and {total_mb}, got {value}")
    return value


ENV_SCHEMA = {
    "DEVICE_ID": {"type": str, "required": True},
    "IFACE": {"type": str, "required": True, "system_validator": validate_iface},
    "CAPTURE": {"type": str, "required": True, "choices": ["AF_PACKET", "PCAP"]},
    "CPU_WORKERS": {
        "type": int,
        "required": True,
        "system_validator": validate_cpu_workers,
    },
    "MEMCAP_MB": {
        "type": int,
        "required": True,
        "system_validator": validate_memcap_mb,
    },
    "PROFILE": {
        "type": str,
        "required": True,
        "choices": ["connectivity", "balanced", "security", "performance"],
    },
    "RULESET": {
        "type": list,
        "required": True,
        "parser": lambda v: [x.strip() for x in v.split(",") if x.strip()],
    },
    "LOG_ROTATE_MB": {"type": int, "required": True, "min": 1},
    "LOG_RETENTION_DAYS": {"type": int, "required": True, "min": 1},
    "SURICATA_CONFIG": {"type": str, "required": True},
    "SURICATA_CLASSIFICATION": {"type": str, "required": False},
    "SURICATA_REFERENCE": {"type": str, "required": False},
    "SURICATA_THRESHOLD": {"type": str, "required": False},
    "SURICATA_UPDATE": {"type": str, "required": False},
    "DOCKER_IMAGE": {"type": str, "required": False},
    "CONTAINER_NAME": {"type": str, "required": False},
    "DOCKER_VOLUME": {"type": str, "required": False},
}

VOLUMES = {
    "DOCKER_VOLUME": {"bind": "/var/log/suricata", "mode": "rw"},
    "SURICATA_CONFIG": {"bind": "/etc/suricata/suricata.yaml", "mode": "rw"},
    "SURICATA_CLASSIFICATION": {
        "bind": "/etc/suricata/classification.config",
        "mode": "rw",
    },
    "SURICATA_REFERENCE": {"bind": "/etc/suricata/reference.config", "mode": "rw"},
    "SURICATA_THRESHOLD": {"bind": "/etc/suricata/threshold.config", "mode": "rw"},
    "SURICATA_UPDATE": {"bind": "/etc/suricata/update.yaml", "mode": "rw"},
}


class SuricataManager:
    def __init__(self):
        self.client = docker.from_env()
        self.image_name = os.getenv("SCTL_DOCKER_IMAGE") or "suricata/suricata:latest"
        self.container_name = os.getenv("SCTL_CONTAINER_NAME") or "suricata"
        self.container = None

    def __load_env(self, schema, prefix=ENV_PREFIX):
        config = {}

        for key, rules in schema.items():
            env_key = f"{prefix}{key}"
            raw = os.getenv(env_key)
            if rules.get("required") and raw is None:
                raise ValueError(f"Missing required env var: {env_key}")
            if raw is None:
                continue
            expected_type = rules.get("type")

            try:
                if expected_type is int:
                    value = int(raw)
                elif expected_type is float:
                    value = float(raw)
                elif expected_type is bool:
                    value = raw.lower() in ("1", "true", "yes", "on")
                elif expected_type is list:
                    parser = rules.get("parser")
                    if not parser:
                        raise ValueError(f"List env var {env_key} requires parser")
                    value = parser(raw)
                else:
                    value = raw

            except Exception:
                raise ValueError(
                    f"Invalid type for {env_key}: expected {expected_type.__name__}, got '{raw}'"
                )

            if "min" in rules and value < rules["min"]:
                raise ValueError(f"{env_key} must be >= {rules['min']} (got {value})")

            if "max" in rules and value > rules["max"]:
                raise ValueError(f"{env_key} must be <= {rules['max']} (got {value})")

            if "choices" in rules and value not in rules["choices"]:
                allowed = ", ".join(rules["choices"])
                raise ValueError(
                    f"{env_key} must be one of [{allowed}] (got '{value}')"
                )

            if "system_validator" in rules:
                value = rules["system_validator"](value)

            config[key.lower()] = value

        return config

    def __ensure_image_exists(self):
        try:
            self.client.images.get(self.image_name)
        except NotFound:
            print(f"Pulling image {self.image_name}...")
            self.client.images.pull(self.image_name)

    def __load_volumes(self):
        volumes = {}
        for volume in VOLUMES:
            if os.getenv(f"{ENV_PREFIX}{volume}") is not None:
                host_path = os.getenv(f"{ENV_PREFIX}{volume}")
                volumes[host_path] = VOLUMES[volume]

        return volumes

    def __start_suricata(self, volumes: dict, interface: str, config_path: str):
        containers = self.client.containers.list(
            all=True, filters={"name": self.container_name}
        )
        old = containers[0] if containers else None
        if old is not None:
            if old.status == "running":
                print(f"Container {old.name} is already running, skipping start.")
                return
            old.remove(force=True)
        self.container = self.client.containers.run(
            self.image_name,
            name=self.container_name,
            detach=True,
            volumes=volumes,
            network_mode="host",
            cap_add=["NET_ADMIN", "NET_RAW"],
            command=[
                "-c",
                config_path,
                "-i",
                interface,
            ],
        )
        print(f"Container {self.container.name} started.")
        return self.container

    def __stop_suricata(self):
        if self.container is None:
            try:
                self.container = self.client.containers.get(self.container_name)
            except Exception:
                print("No container to stop.")
                return

        if self.container.status == "running":
            self.container.stop()
            print(f"Container {self.container.name} stopped.")
        else:
            print("Container is not running.")

    def start(self):
        try:
            config = self.__load_env(ENV_SCHEMA)
            volumes = self.__load_volumes()
            self.__ensure_image_exists()
            self.__set_suricata_config(**config)
            self.__set_log_rotate_config(
                os.getenv("{ENV_PREFIX}LOG_ROTATE_MB"),
                os.getenv(f"{ENV_PREFIX}LOG_RETENTION_DAYS"),
                os.getenv(f"{ENV_PREFIX}DOCKER_VOLUME"),
            )
            self.__start_suricata(
                volumes,
                config["iface"],
                volumes[os.getenv(f"{ENV_PREFIX}SURICATA_CONFIG")]["bind"],
            )

        except Exception as e:
            print(f"Error occurred while starting suricata docker: {e}")

    def __clean_up_logs(self):
        log_volume = os.getenv(f"{ENV_PREFIX}DOCKER_VOLUME")
        if log_volume is None:
            print("No DOCKER_VOLUME specified, skipping log clean up.")
            return

        if os.path.exists(log_volume):
            try:
                shutil.rmtree(log_volume)
                print(f"Removed log dir: {log_volume}")
            except Exception as e:
                print(f"Failed to remove log dir {log_volume}: {e}")
        else:
            print(f"No log file found at: {log_volume}")

    def stop(self, clean_up: bool = False):
        self.__stop_suricata()
        if clean_up:
            self.__clean_up_logs()

    def remove(self):
        if self.container is None:
            try:
                self.container = self.client.containers.get(self.container_name)
            except Exception:
                print("No container to remove.")
                return

        self.container.remove(force=True)
        print(f"Container {self.container.name} removed.")
        self.container = None

    def __set_log_rotate_config(
        self, rotate_size_mb: int, retention_days: int, log_path: str
    ):
        # Build config content
        content = f"""
    {log_path}/*.log
    {log_path}/*.json {{
        daily
        size {rotate_size_mb}M
        rotate {retention_days}
        missingok
        notifempty
        compress
        delaycompress
        copytruncate
    }}
    """.lstrip()
        with open(LOG_ROTATE_CONFIG_PATH, "w") as f:
            f.write(content)

    def __set_suricata_config(
        self,
        device_id: str,
        iface: str,
        capture,
        cpu_workers,
        memcap_mb,
        profile: str,
        ruleset: list[str],
        suricata_config: str,
        **kwargs,
    ):
        with open(suricata_config, "r") as f:
            cfg = yaml.safe_load(f)
        cfg.setdefault("metadata", {})
        cfg["metadata"]["sensor-name"] = device_id

        cap = capture.upper()

        if cap == "AF_PACKET":
            if (
                "af-packet" not in cfg
                or not isinstance(cfg["af-packet"], list)
                or len(cfg["af-packet"]) == 0
            ):
                cfg["af-packet"] = [{}]
            cfg["af-packet"][0]["enabled"] = True

            if "pcap" in cfg and isinstance(cfg["pcap"], list) and len(cfg["pcap"]) > 0:
                cfg["pcap"][0]["enabled"] = False

        elif cap == "PCAP":
            if (
                "pcap" not in cfg
                or not isinstance(cfg["pcap"], list)
                or len(cfg["pcap"]) == 0
            ):
                cfg["pcap"] = [{}]
            cfg["pcap"][0]["enabled"] = True

            if (
                "af-packet" in cfg
                and isinstance(cfg["af-packet"], list)
                and len(cfg["af-packet"]) > 0
            ):
                cfg["af-packet"][0]["enabled"] = False

        else:
            raise ValueError(f"Invalid CAPTURE mode: {capture}. Use AF_PACKET or PCAP.")

        if cap == "AF_PACKET":
            cfg["af-packet"][0]["interface"] = iface
        elif cap == "PCAP":
            cfg["pcap"][0]["interface"] = iface

        if "af-packet" in cfg and isinstance(cfg["af-packet"], list):
            cfg["af-packet"][0]["threads"] = cpu_workers

        cfg.setdefault("flow", {})
        cfg["flow"]["memcap"] = f"{memcap_mb}mb"

        eve_log = {
            "enabled": True,
            "filetype": "regular",
            "filename": "eve.json",
            "community-id": True,
            "include-metadata": True,
            "custom-fields": {"device-id": device_id},
            "types": ["alert", "flow", "dns", "http", "tls", "ssh", "netflow", "stats"],
        }

        new_outputs = []
        eve_found = False

        for output in cfg.get("outputs", []):
            if "eve-log" in output:
                new_outputs.append({"eve-log": eve_log})
                eve_found = True
            else:
                new_outputs.append(output)

        if not eve_found:
            new_outputs.append({"eve-log": eve_log})

        cfg["outputs"] = new_outputs

        cfg.setdefault("detect-engine", [{}])
        cfg["detect-engine"][0]["profile"] = profile.lower()

        cfg["rule-files"] = ruleset

        with open(suricata_config, "w") as f:
            f.write("%YAML 1.1\n")
            f.write("---\n")
            yaml.safe_dump(cfg, f, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(
        description="Suricata Manager - start/stop controller"
    )
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--start", action="store_true", help="Start Suricata")
    action_group.add_argument("--stop", action="store_true", help="Stop Suricata")
    parser.add_argument(
        "--clean-up",
        action="store_true",
        help="Clean up Suricata temporary files (only valid with --stop)",
    )

    args = parser.parse_args()

    if args.clean_up and not args.stop:
        parser.error("--clean-up can only be used together with --stop")

    manager = SuricataManager()

    if args.start:
        print("Starting Suricata...")
        manager.start()

    elif args.stop:
        print("Stopping Suricata...")
        manager.stop(args.clean_up)


if __name__ == "__main__":
    main()
