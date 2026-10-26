use std::os::unix::process::CommandExt;

/// Register a `pre_exec` hook that calls `setsid()` to detach the child
/// into its own session.
pub fn pre_exec_setsid(cmd: &mut impl CommandExt) {
    // SAFETY: setsid() is async-signal-safe per POSIX.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

/// Register a `pre_exec` hook that calls `setpgid(0, 0)` to place the
/// child in its own process group.
pub fn pre_exec_setpgid(cmd: &mut impl CommandExt) {
    // SAFETY: setpgid() is async-signal-safe per POSIX.
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
}

/// Register a `pre_exec` hook that calls `prctl(PR_SET_PDEATHSIG, SIGTERM)`
/// so the child receives SIGTERM when its parent dies.
#[cfg(target_os = "linux")]
pub fn pre_exec_pdeathsig(cmd: &mut impl CommandExt) {
    // SAFETY: prctl(PR_SET_PDEATHSIG, ...) is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
}

/// Register a `pre_exec` hook that calls `setrlimit(RLIMIT_AS, ...)` to cap
/// the child's total virtual address space at `bytes`, both soft and hard.
/// Linux-only: this is how the workflow-validation subprocess (see
/// `fabro-server::validation_runner`) bounds memory, since macOS's
/// `ulimit -v`/`RLIMIT_AS` does not actually cap process memory there.
#[cfg(target_os = "linux")]
pub fn pre_exec_rlimit_as(cmd: &mut impl CommandExt, bytes: u64) {
    // SAFETY: setrlimit() is async-signal-safe per POSIX.
    unsafe {
        cmd.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: bytes as libc::rlim_t,
                rlim_max: bytes as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &raw const limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
