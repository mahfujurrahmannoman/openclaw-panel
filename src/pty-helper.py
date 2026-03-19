#!/usr/bin/env python3
"""
PTY helper for OpenClaw Panel.
Creates a real pseudo-terminal and runs docker exec inside it.
This avoids the fragile 'script' wrapper and doesn't need node-pty.

Usage: python3 pty-helper.py <container_id> [cols] [rows]

The parent process communicates via stdin/stdout (raw bytes).
Resize: send the string RESIZE:cols:rows\n on fd 3 (or via env).
"""
import os, sys, pty, select, signal, struct, fcntl, termios

def set_winsize(fd, rows, cols):
    """Set the window size of a PTY."""
    winsize = struct.pack('HHHH', rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

def main():
    if len(sys.argv) < 2:
        print("Usage: pty-helper.py <container_id> [cols] [rows]", file=sys.stderr)
        sys.exit(1)

    container_id = sys.argv[1]
    cols = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    rows = int(sys.argv[3]) if len(sys.argv) > 3 else 30

    # Create a new PTY
    master_fd, slave_fd = pty.openpty()

    # Set initial window size
    set_winsize(master_fd, rows, cols)

    # Fork and exec docker in the child
    pid = os.fork()
    if pid == 0:
        # Child process
        os.close(master_fd)
        os.setsid()

        # Set the slave as controlling terminal
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        # Redirect stdio to the PTY slave
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)

        # Exec docker
        os.execlp('docker', 'docker', 'exec', '-it',
                   '-e', 'TERM=xterm-256color',
                   container_id, '/bin/bash')
    else:
        # Parent process
        os.close(slave_fd)

        # Make stdin non-blocking
        flags = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # Handle SIGWINCH (window resize) - resize the PTY
        def handle_sigwinch(signum, frame):
            pass  # Resize is handled via stdin protocol
        signal.signal(signal.SIGWINCH, handle_sigwinch)

        # Handle SIGCHLD - child exited
        child_exited = [False]
        def handle_sigchld(signum, frame):
            child_exited[0] = True
        signal.signal(signal.SIGCHLD, handle_sigchld)

        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()

        # Make stdout raw/unbuffered
        try:
            os.set_inheritable(stdout_fd, True)
        except:
            pass

        buf = b''
        try:
            while not child_exited[0]:
                try:
                    rfds, _, _ = select.select([master_fd, stdin_fd], [], [], 1.0)
                except (select.error, OSError, InterruptedError):
                    if child_exited[0]:
                        break
                    continue

                if master_fd in rfds:
                    try:
                        data = os.read(master_fd, 65536)
                        if not data:
                            break
                        os.write(stdout_fd, data)
                    except OSError:
                        break

                if stdin_fd in rfds:
                    try:
                        data = os.read(stdin_fd, 65536)
                        if not data:
                            break

                        # Check for resize command: \x1b[RESIZE:cols:rows
                        buf += data
                        while b'\x1bRESIZE:' in buf:
                            idx = buf.index(b'\x1bRESIZE:')
                            # Write everything before the resize command to the PTY
                            if idx > 0:
                                os.write(master_fd, buf[:idx])
                            # Parse resize
                            rest = buf[idx + 8:]  # after \x1bRESIZE:
                            nl = rest.find(b'\n')
                            if nl == -1:
                                buf = buf[idx:]  # incomplete, wait for more
                                break
                            resize_str = rest[:nl].decode('ascii', errors='ignore')
                            buf = rest[nl + 1:]
                            try:
                                c, r = resize_str.split(':')
                                set_winsize(master_fd, int(r), int(c))
                            except:
                                pass
                        else:
                            # No resize commands, write all to PTY
                            if buf:
                                os.write(master_fd, buf)
                                buf = b''
                    except OSError:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            os.close(master_fd)
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass
            try:
                os.waitpid(pid, 0)
            except:
                pass

if __name__ == '__main__':
    main()
