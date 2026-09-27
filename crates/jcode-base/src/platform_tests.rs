use super::*;

#[test]
fn desired_nofile_soft_limit_only_raises_when_possible() {
    assert_eq!(desired_nofile_soft_limit(1024, 524_288, 8192), Some(8192));
    assert_eq!(desired_nofile_soft_limit(8192, 524_288, 8192), None);
    assert_eq!(desired_nofile_soft_limit(1024, 4096, 8192), Some(4096));
}

#[cfg(unix)]
#[test]
fn spawn_detached_creates_new_session() {
    use std::io::{self, Read};
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    struct OwnedChild(Child);

    impl OwnedChild {
        fn cleanup(&mut self) -> io::Result<ExitStatus> {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            self.0.kill()?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = self.0.try_wait()? {
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "child cleanup"));
                }
                std::thread::yield_now();
            }
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                if std::thread::panicking() {
                    eprintln!("test child cleanup failed: {error}");
                } else {
                    panic!("test child cleanup failed: {error}");
                }
            }
        }
    }

    let parent_sid = unsafe { libc::getsid(0) };
    assert!(parent_sid > 0, "read parent session ID");

    for detached in [false, true] {
        // Only shell builtins: no descendants. Hold stdin open until cleanup so
        // the ready child remains alive while its session ID is inspected.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf R; read -r release"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = OwnedChild(if detached {
            super::spawn_detached(&mut cmd).expect("spawn detached child")
        } else {
            cmd.spawn().expect("spawn ordinary child")
        });

        let stdout = child.0.stdout.as_mut().expect("child readiness pipe");
        let mut ready = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "child readiness timed out");
            let timeout = remaining.as_millis().max(1) as i32;
            let result = unsafe { libc::poll(&mut ready, 1, timeout) };
            if result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            assert!(result > 0, "child readiness poll failed or timed out");
            assert_ne!(ready.revents & libc::POLLIN, 0, "child exited before ready");
            break;
        }
        let mut byte = [0];
        stdout.read_exact(&mut byte).expect("read readiness byte");
        assert_eq!(byte, [b'R']);
        assert!(child.0.try_wait().expect("check child is alive").is_none());

        let child_pid = child.0.id() as libc::pid_t;
        let child_sid = unsafe { libc::getsid(child_pid) };
        assert!(child_sid > 0, "read live child session ID");
        if detached {
            assert_eq!(
                child_sid, child_pid,
                "detached child should lead its own session"
            );
            assert_ne!(
                child_sid, parent_sid,
                "detached child should not share parent session"
            );
            // Exercise the same guard cleanup used when an assertion unwinds.
            let unwind = std::panic::catch_unwind(move || -> () {
                let _owned_child = child;
                std::panic::resume_unwind(Box::new(()));
            });
            assert!(unwind.is_err());
        } else {
            assert_eq!(
                child_sid, parent_sid,
                "ordinary child should share parent session"
            );
            child.cleanup().expect("terminate and reap test child");
            drop(child);
        }
        let wait_result = unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(wait_result, -1, "test child should already be reaped");
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    }
}

#[cfg(windows)]
#[test]
fn is_process_running_reports_exited_children_as_stopped() {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let mut cmd = Command::new("cmd.exe");
    cmd.args(["/C", "ping -n 3 127.0.0.1 >NUL"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().expect("spawn child");
    let pid = child.id();
    assert!(
        super::is_process_running(pid),
        "child should initially be running"
    );

    let status = child.wait().expect("wait for child");
    assert!(status.success(), "child should exit successfully");
    std::thread::sleep(Duration::from_millis(100));

    assert!(
        !super::is_process_running(pid),
        "exited child should not be reported as running"
    );
}

#[cfg(windows)]
#[test]
fn signal_detached_process_group_terminates_descendant_tree() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let temp = tempfile::tempdir().expect("temp dir");
    let ready_path = temp.path().join("child-ready.txt");
    let survived_path = temp.path().join("child-survived.txt");
    let child_script_path = temp.path().join("child.cmd");
    let parent_script_path = temp.path().join("parent.cmd");
    let child_script = concat!(
        "@echo off\r\n",
        "echo ready>\"%~dp0child-ready.txt\"\r\n",
        "ping -n 6 127.0.0.1 >NUL\r\n",
        "echo survived>\"%~dp0child-survived.txt\"\r\n"
    );
    let parent_script = concat!(
        "@echo off\r\n",
        "start \"\" /B cmd.exe /D /C \"\"%~dp0child.cmd\"\"\r\n",
        "ping -n 30 127.0.0.1 >NUL\r\n"
    );
    std::fs::write(&child_script_path, child_script).expect("write child command script");
    std::fs::write(&parent_script_path, parent_script).expect("write parent command script");
    let mut cmd = Command::new("cmd.exe");
    cmd.args(["/D", "/C"])
        .arg(&parent_script_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut parent = super::spawn_detached(&mut cmd).expect("spawn detached process tree");
    let parent_pid = parent.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready_path.exists(), "descendant should report ready");
    assert!(super::is_process_running(parent_pid));

    super::signal_detached_process_group(parent_pid, 0).expect("terminate process tree");
    let deadline = Instant::now() + Duration::from_secs(10);
    while super::is_process_running(parent_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = parent.wait();

    assert!(!super::is_process_running(parent_pid), "parent should stop");
    std::thread::sleep(Duration::from_secs(6));
    assert!(
        !survived_path.exists(),
        "descendant should not survive termination of the detached process tree"
    );
}

#[cfg(windows)]
#[test]
fn spawn_replacement_process_returns_without_waiting_for_child_exit() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut cmd = Command::new("cmd.exe");
    cmd.args(["/C", "ping -n 4 127.0.0.1 >NUL"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let start = Instant::now();
    let mut child = super::spawn_replacement_process(&mut cmd)
        .expect("spawn replacement process should succeed");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "replacement spawn should not block, took {:?}",
        elapsed
    );
    assert!(
        child.try_wait().expect("poll child status").is_none(),
        "replacement child should still be running immediately after spawn"
    );

    child.kill().ok();
    let _ = child.wait();
}
