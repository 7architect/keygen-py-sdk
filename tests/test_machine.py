from __future__ import annotations

import threading
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

import keygen
from keygen import heartbeat
from keygen.heartbeat import HeartbeatMonitor

from conftest import body_of
from helpers import machine_resource


def process_resource(id_="proc-1", interval=600, status="ALIVE"):
    return {
        "id": id_,
        "type": "processes",
        "attributes": {"pid": "123", "status": status, "interval": interval, "metadata": {}},
        "relationships": {"machine": {"data": {"type": "machines", "id": "mach-1"}}},
    }


def wait_for(condition, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def fast_heartbeats(monkeypatch):
    monkeypatch.setattr(heartbeat, "schedule", lambda duration: (0.05, 0.5))


class TestSchedule:
    @pytest.mark.parametrize(
        "duration,interval",
        [(600, 570.0), (61, 31.0), (60, 30.0), (30, 15.0), (1, 1.0), (0, 570.0), (-10, 570.0)],
    )
    def test_intervals(self, duration, interval):
        assert heartbeat.schedule(duration)[0] == interval

    def test_retry_window_fits_inside_the_leeway(self):
        interval, window = heartbeat.schedule(600)
        assert 0 < window < 600 - interval


class TestHeartbeatMonitor:
    def test_pings_until_stopped(self, fast_heartbeats):
        calls = []
        monitor = HeartbeatMonitor(lambda: calls.append(1), 600).start()
        assert wait_for(lambda: len(calls) >= 3)
        monitor.stop()
        count = len(calls)
        time.sleep(0.15)
        assert len(calls) == count
        assert not monitor.running

    def test_context_manager(self, fast_heartbeats):
        with HeartbeatMonitor(lambda: None, 600).start() as monitor:
            assert monitor.running
        assert not monitor.running

    def test_fatal_error_stops_and_reports(self, fast_heartbeats):
        reported = []

        def ping():
            raise keygen.HeartbeatDeadError()

        monitor = HeartbeatMonitor(ping, 600, on_error=reported.append).start()
        assert wait_for(lambda: reported)
        assert isinstance(monitor.error, keygen.HeartbeatDeadError)
        assert wait_for(lambda: not monitor.running)

    def test_transient_errors_are_retried(self, fast_heartbeats):
        attempts = []
        succeeded = threading.Event()

        def ping():
            attempts.append(1)
            if len(attempts) < 2:
                raise keygen.NetworkError("offline")
            succeeded.set()

        monitor = HeartbeatMonitor(ping, 600).start()
        assert succeeded.wait(5)
        monitor.stop()
        assert monitor.error is None

    def test_broken_error_handler_does_not_crash(self, fast_heartbeats):
        def ping():
            raise keygen.MachineNotFoundError()

        def handler(err):
            raise RuntimeError("handler bug")

        monitor = HeartbeatMonitor(ping, 600, on_error=handler).start()
        assert wait_for(lambda: monitor.error is not None)


class TestMachine:
    def test_monitor(self, api, fast_heartbeats):
        pings = []

        def pong(request):
            pings.append(request)
            return 200, {}, {"data": machine_resource(heartbeatStatus="ALIVE")}

        api.add("POST", r"/machines/mach-1/actions/ping$", pong)
        api.add("DELETE", r"/machines/mach-1$", (204, {}, ""))

        machine = keygen.Machine(id="mach-1", heartbeat_status="NOT_STARTED")
        monitor = machine.monitor()
        assert machine.heartbeat_status == keygen.HeartbeatStatus.ALIVE
        assert machine.monitor() is monitor
        assert wait_for(lambda: len(pings) >= 3)

        machine.deactivate()
        assert not monitor.running

    def test_first_ping_failure_raises(self, api):
        api.add("POST", r"/actions/ping$", (422, {}, {"errors": [{"code": "MACHINE_HEARTBEAT_DEAD"}]}))
        machine = keygen.Machine(id="mach-1")
        with pytest.raises(keygen.HeartbeatDeadError):
            machine.monitor()
        assert machine.heartbeat is None

    def test_later_ping_failure(self, api, fast_heartbeats):
        responses = iter([(200, {}, {"data": machine_resource()})])

        def pong(request):
            return next(responses, (404, {}, {"errors": [{"code": "NOT_FOUND"}]}))

        api.add("POST", r"/actions/ping$", pong)
        errors = []
        monitor = keygen.Machine(id="mach-1").monitor(on_error=errors.append)
        assert wait_for(lambda: errors)
        assert isinstance(errors[0], keygen.NotFoundError)
        assert isinstance(monitor.error, keygen.NotFoundError)

    def test_checkout_defaults(self, api):
        api.add(
            "POST",
            r"/machines/mach-1/actions/check-out",
            (200, {}, {"data": {"id": "mf", "type": "machine-files", "attributes": {"certificate": "C"},
                                "relationships": {"machine": {"data": {"type": "machines", "id": "mach-1"}},
                                                  "license": {"data": {"type": "licenses", "id": "lic-1"}}}}}),
        )
        mic = keygen.Machine(id="mach-1").checkout(ttl=3600)
        query = {k: v[0] for k, v in parse_qs(urlsplit(api.last.url).query).items()}
        assert query == {"algorithm": "aes-256-gcm+ed25519", "encrypt": "true", "include": "license,license.entitlements", "ttl": "3600"}
        assert (mic.machine_id, mic.license_id, mic.certificate) == ("mach-1", "lic-1", "C")
        assert len(api.requests) == 1

    def test_components(self, api):
        api.add(
            "GET",
            r"/machines/mach-1/components\?limit=100$",
            (200, {}, {"data": [{"id": "c1", "type": "components", "attributes": {"fingerprint": "disk", "name": "Disk"},
                                 "relationships": {"machine": {"data": {"type": "machines", "id": "mach-1"}}}}]}),
        )
        components = keygen.Machine(id="mach-1").components()
        assert components[0].fingerprint == "disk" and components[0].machine_id == "mach-1"

    def test_spawn_and_kill(self, api, fast_heartbeats):
        pings = []
        api.add("POST", r"/processes$", (201, {}, {"data": process_resource()}))
        api.add("POST", r"/processes/proc-1/actions/ping$", lambda r: pings.append(r) or (200, {}, {"data": process_resource()}))
        api.add("DELETE", r"/processes/proc-1$", (204, {}, ""))

        process = keygen.Machine(id="mach-1").spawn(123)

        create = [r for r in api.requests if r.url.endswith("/processes")][0]
        assert body_of(create) == {
            "data": {
                "type": "processes",
                "attributes": {"pid": "123"},
                "relationships": {"machine": {"data": {"type": "machines", "id": "mach-1"}}},
            }
        }
        assert process.status == keygen.ProcessStatus.ALIVE
        assert process.machine_id == "mach-1"
        assert wait_for(lambda: len(pings) >= 2)

        process.kill()
        assert not process.heartbeat.running

    def test_spawn_over_limit(self, api):
        api.add("POST", r"/processes$", (422, {}, {"errors": [{"code": "MACHINE_PROCESS_LIMIT_EXCEEDED"}]}))
        with pytest.raises(keygen.ProcessLimitExceededError):
            keygen.Machine(id="mach-1").spawn("1")

    def test_spawn_requires_pid(self):
        with pytest.raises(ValueError):
            keygen.Machine(id="mach-1").spawn("")

    def test_processes(self, api):
        api.add("GET", r"/machines/mach-1/processes\?limit=100$", (200, {}, {"data": [process_resource("p1"), process_resource("p2")]}))
        assert [p.id for p in keygen.Machine(id="mach-1").processes()] == ["p1", "p2"]

    def test_requires_id(self):
        with pytest.raises(ValueError):
            keygen.Machine().deactivate()
        with pytest.raises(ValueError):
            keygen.Process().kill()

    def test_concurrent_requests(self, api):
        api.add("GET", r"/machines/", (200, {}, {"data": machine_resource()}))
        license = keygen.License(id="lic-1")
        results = []
        threads = [threading.Thread(target=lambda: results.append(license.machine("fp"))) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(results) == 8

    def test_timeouts_are_applied(self, api):
        seen = []
        original = api.send

        def send(request, **kwargs):
            seen.append(kwargs.get("timeout"))
            return original(request, **kwargs)

        api.send = send
        api.add("GET", r"/machines/", (200, {}, {"data": machine_resource()}))
        keygen.timeout = 7
        keygen.License(id="lic-1").machine("fp")
        assert seen == [7]

    def test_network_errors_during_ping(self, api):
        api.error = requests.Timeout("slow")
        with pytest.raises(keygen.NetworkError):
            keygen.Machine(id="mach-1").ping()
