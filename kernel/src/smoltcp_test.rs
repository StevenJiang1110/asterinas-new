use core::slice::SlicePattern;

use ostd::{arch::qemu::{exit_qemu, QemuExitCode}, sync::LocalIrqDisabled};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, Loopback, Medium},
    socket::tcp,
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr},
};

use crate::{prelude::*, time::clocks::MonotonicClock, Clock};

const MSG_SIZE: usize = 4096;
const BUF_SIZE: usize = 65536;

pub fn test_smoltcp_bandwidth() {
    let device = Mutex::new(Loopback::new(Medium::Ethernet));

    let config = match device.lock().capabilities().medium {
        Medium::Ethernet => {
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
    };

    let clock = MonotonicClock::get();
    let iface: SpinLock<Interface, LocalIrqDisabled> = {
        let mut iface = Interface::new(config, &mut *device.lock(), instant_now(clock));
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
        SpinLock::new(iface)
    };

    // Create sockets
    let server_socket = {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; BUF_SIZE]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; BUF_SIZE]);
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let client_socket = {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65536]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65536]);
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let (sockets, server_handle, client_handle) = {
        let mut sockets = SocketSet::new(Vec::new());
        let server_handle = sockets.add(server_socket);
        let client_handle = sockets.add(client_socket);
        (SpinLock::<_, LocalIrqDisabled>::new(sockets), server_handle, client_handle)
    };

    let start_time = clock.read_time();

    let mut recv_buffer = vec![123; BUF_SIZE];
    let send_buffer = vec![124; BUF_SIZE];
    let mut did_listen = false;
    let mut did_connect = false;
    let mut processed = 0;
    while processed < 64 * 1024 * 1024 * 1024 {
        poll(clock, &device, &sockets, &iface);

        // Receive
        loop {
            let mut sockets_guard = sockets.lock();
            let socket = sockets_guard.get_mut::<tcp::Socket>(server_handle);
            if !socket.is_active() && !socket.is_listening() && !did_listen {
                debug!("listening");
                socket.listen(1234).unwrap();
                did_listen = true;
            }

            if !socket.can_recv() {
                break;
            }

            let received = socket
                .recv(|buffer| {
                    let mut writer = VmWriter::from(&mut recv_buffer[..buffer.len()]).to_fallible();
                    let received = writer
                        .write_fallible(&mut VmReader::from(buffer.as_slice()))
                        .unwrap();

                    (received, received)
                })
                .unwrap();
            debug!("got {:?}", received);
            processed += received;

            drop(sockets_guard);

            poll(clock, &device, &sockets, &iface);
        }

        // Send
        loop {
            let mut iface_guard = iface.lock();
            let mut sockets_guard = sockets.lock();
            let socket = sockets_guard.get_mut::<tcp::Socket>(client_handle);
            let cx = iface_guard.context();
            if !socket.is_open() && !did_connect {
                // debug!("connecting");
                socket
                    .connect(cx, (IpAddress::v4(127, 0, 0, 1), 1234), 65000)
                    .unwrap();
                did_connect = true;

                drop(sockets_guard);
                drop(iface_guard);

                poll(clock, &device, &sockets, &iface);
                break;
            }

            if !socket.can_send() {
                drop(sockets_guard);
                drop(iface_guard);
                poll(clock, &device, &sockets, &iface);
                break;
            }

            debug!("sending");
            socket
                .send(|buffer| {
                    let len = buffer.len();
                    let mut reader = VmReader::from(&send_buffer[..len]);
                    let mut writer = VmWriter::from(buffer).to_fallible();
                    let sent = writer.write_fallible(&mut reader).unwrap();
                    (sent, ())
                })
                .unwrap();

            drop(sockets_guard);
            drop(iface_guard);

            poll(clock, &device, &sockets, &iface);
        }
    } 

    let duration = clock.read_time() - start_time;
    println!(
        "done in {} s, bandwidth is {} Gbps",
        duration.as_millis() as f64 / 1000.0,
        (processed as u64 * 8 / duration.as_millis() as u64) as f64 / 1000000.0
    );

    exit_qemu(QemuExitCode::Success)
}

fn instant_now(clock: &Arc<MonotonicClock>) -> Instant {
    Instant::from_micros(clock.read_time().as_micros() as i64)
}

fn poll(clock: &Arc<MonotonicClock>, device: &Mutex<Loopback>, sockets: &SpinLock<SocketSet, LocalIrqDisabled>, iface: &SpinLock<Interface, LocalIrqDisabled>) {
    let mut device = device.lock();
    let mut iface = iface.lock();
    let mut sockets = sockets.lock();
    iface.poll(instant_now(clock), &mut *device, &mut sockets);
}